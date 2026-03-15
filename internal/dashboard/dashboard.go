package dashboard

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/AnassElhamri/ssh-honeypot/internal/analyzer"
	"github.com/AnassElhamri/ssh-honeypot/internal/logger"
)

// Dashboard is the live terminal UI.
type Dashboard struct {
	app       *tview.Application
	db        *logger.DB
	tracker   *analyzer.Tracker
	refreshMs int

	headerBox  *tview.TextView
	statsBox   *tview.TextView
	liveBox    *tview.Table
	credsBox   *tview.Table
	countryBox *tview.Table
	logBox     *tview.TextView

	mu        sync.Mutex
	logLines  []string
	startTime time.Time
	onBlock   func(string)
}

// New creates the dashboard.
func New(db *logger.DB, tracker *analyzer.Tracker, refreshMs int, onBlock func(string)) *Dashboard {
	d := &Dashboard{
		db:        db,
		tracker:   tracker,
		refreshMs: refreshMs,
		startTime: time.Now(),
		onBlock:   onBlock,
	}
	d.build()
	return d
}

func (d *Dashboard) build() {
	d.app = tview.NewApplication()

	d.headerBox = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	d.headerBox.SetBorder(false)
	d.headerBox.SetText(
		"[cyan::b]⚠  SSH HONEYPOT  ⚠[-:-:-]  " +
			"[gray]Real-time attack monitoring[-]")

	d.statsBox = tview.NewTextView().SetDynamicColors(true)
	d.statsBox.SetBorder(true).
		SetTitle(" [yellow] Statistics[-] ").
		SetTitleAlign(tview.AlignLeft)

	d.liveBox = tview.NewTable().SetFixed(1, 0).SetSelectable(true, false)
	d.liveBox.SetBorder(true).
		SetTitle(" [red]🔴 Active Sessions (Select + 'b' to Block)[-] ").
		SetTitleAlign(tview.AlignLeft)
	d.setLiveHeaders()

	d.credsBox = tview.NewTable().SetFixed(1, 0).SetSelectable(false, false)
	d.credsBox.SetBorder(true).
		SetTitle(" [yellow]🔑 Top Passwords Tried[-] ").
		SetTitleAlign(tview.AlignLeft)

	d.countryBox = tview.NewTable().SetFixed(1, 0).SetSelectable(false, false)
	d.countryBox.SetBorder(true).
		SetTitle(" [green]🌍 Top Countries[-] ").
		SetTitleAlign(tview.AlignLeft)

	d.logBox = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetMaxLines(200)
	d.logBox.SetBorder(true).
		SetTitle(" [white]📋 Live Event Log[-] ").
		SetTitleAlign(tview.AlignLeft)

	topRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.statsBox, 32, 0, false).
		AddItem(d.liveBox, 0, 1, false)

	midRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.credsBox, 0, 1, false).
		AddItem(d.countryBox, 0, 1, false)

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(d.headerBox, 2, 0, false).
		AddItem(topRow, 12, 0, false).
		AddItem(midRow, 14, 0, false).
		AddItem(d.logBox, 0, 1, false)

	d.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc || event.Rune() == 'q' {
			d.app.Stop()
		}
		if event.Rune() == 'b' {
			row, _ := d.liveBox.GetSelection()
			if row > 0 {
				ipCell := d.liveBox.GetCell(row, 1)
				if ipCell != nil && d.onBlock != nil {
					d.onBlock(ipCell.Text)
				}
			}
		}
		return event
	})

	d.app.SetRoot(layout, true)
}

func (d *Dashboard) setLiveHeaders() {
	headers := []string{"SESSION", "IP ADDRESS", "COUNTRY", "CREDS", "CMDS", "THREAT", "DURATION"}
	for i, h := range headers {
		d.liveBox.SetCell(0, i,
			tview.NewTableCell(h).
				SetTextColor(tcell.ColorYellow).
				SetAttributes(tcell.AttrBold).
				SetExpansion(1))
	}
}

// Start runs the dashboard refresh loop and the tview app.
func (d *Dashboard) Start(onStop func()) {
	go d.refreshLoop()
	go func() {
		if err := d.app.Run(); err != nil {
			// Dashboard error — non-fatal, continue running server
			fmt.Printf("dashboard error: %v\n", err)
		}
		if onStop != nil {
			onStop()
		}
	}()
}

// Stop stops the dashboard.
func (d *Dashboard) Stop() {
	d.app.Stop()
}

// AddLogLine appends a line to the event log panel.
func (d *Dashboard) AddLogLine(line string) {
	d.mu.Lock()
	d.logLines = append(d.logLines, line)
	if len(d.logLines) > 200 {
		d.logLines = d.logLines[len(d.logLines)-200:]
	}
	d.mu.Unlock()
}

func (d *Dashboard) refreshLoop() {
	ticker := time.NewTicker(time.Duration(d.refreshMs) * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		d.refresh()
	}
}

func (d *Dashboard) refresh() {
	stats, err := d.db.GetStats()
	if err != nil {
		return
	}
	active := d.tracker.ActiveSessions()
	uptime := time.Since(d.startTime).Round(time.Second)

	d.app.QueueUpdateDraw(func() {
		d.updateStats(stats, len(active), uptime)
		d.updateLiveSessions(active)
		d.updateTopPasswords(stats)
		d.updateTopCountries(stats)
		d.updateLog()
	})
}

func (d *Dashboard) updateStats(stats *logger.Stats, active int, uptime time.Duration) {
	d.statsBox.Clear()
	fmt.Fprintf(d.statsBox,
		"\n [gray]Uptime:          [white]%s[-]\n\n"+
			" [gray]Total Sessions:  [cyan]%d[-]\n"+
			" [gray]Active Now:      [red]%d[-]\n"+
			" [gray]Unique IPs:      [yellow]%d[-]\n\n"+
			" [gray]Cred Attempts:   [white]%d[-]\n"+
			" [gray]Commands Run:    [white]%d[-]\n",
		uptime,
		stats.TotalSessions,
		active,
		stats.UniqueIPs,
		stats.TotalCredentials,
		stats.TotalCommands,
	)
}

func (d *Dashboard) updateLiveSessions(active map[int64]*analyzer.SessionStats) {
	for d.liveBox.GetRowCount() > 1 {
		d.liveBox.RemoveRow(1)
	}
	row := 1
	for id, s := range active {
		level := s.Level()
		color := tcell.ColorGreen
		switch level {
		case analyzer.ThreatHigh:
			color = tcell.ColorOrange
		case analyzer.ThreatCritical:
			color = tcell.ColorRed
		}
		cells := []string{
			fmt.Sprintf("%d", id),
			s.IP,
			s.GetCountry(),
			fmt.Sprintf("%d", s.CredAttempts),
			fmt.Sprintf("%d", s.Commands),
			fmt.Sprintf("%s(%d)", level, s.ThreatScore()),
			s.Duration().Round(time.Second).String(),
		}
		for col, text := range cells {
			d.liveBox.SetCell(row, col,
				tview.NewTableCell(text).SetTextColor(color).SetExpansion(1))
		}
		row++
	}
}

func (d *Dashboard) updateTopPasswords(stats *logger.Stats) {
	for d.credsBox.GetRowCount() > 0 {
		d.credsBox.RemoveRow(0)
	}
	for i, h := range []string{"PASSWORD", "COUNT"} {
		d.credsBox.SetCell(0, i,
			tview.NewTableCell(h).
				SetTextColor(tcell.ColorYellow).
				SetAttributes(tcell.AttrBold).
				SetExpansion(1))
	}
	for i, entry := range stats.TopPasswords {
		pass := entry.Value
		if len(pass) > 24 {
			pass = pass[:24] + "…"
		}
		d.credsBox.SetCell(i+1, 0,
			tview.NewTableCell(pass).SetTextColor(tcell.ColorWhite).SetExpansion(1))
		d.credsBox.SetCell(i+1, 1,
			tview.NewTableCell(fmt.Sprintf("%d", entry.Count)).
				SetTextColor(tcell.ColorRed).SetExpansion(1))
	}
}

func (d *Dashboard) updateTopCountries(stats *logger.Stats) {
	for d.countryBox.GetRowCount() > 0 {
		d.countryBox.RemoveRow(0)
	}
	for i, h := range []string{"COUNTRY", "SESSIONS"} {
		d.countryBox.SetCell(0, i,
			tview.NewTableCell(h).
				SetTextColor(tcell.ColorYellow).
				SetAttributes(tcell.AttrBold).
				SetExpansion(1))
	}
	for i, entry := range stats.TopCountries {
		d.countryBox.SetCell(i+1, 0,
			tview.NewTableCell(entry.Value).SetTextColor(tcell.ColorGreen).SetExpansion(1))
		d.countryBox.SetCell(i+1, 1,
			tview.NewTableCell(fmt.Sprintf("%d", entry.Count)).
				SetTextColor(tcell.ColorWhite).SetExpansion(1))
	}
}

func (d *Dashboard) updateLog() {
	d.mu.Lock()
	lines := make([]string, len(d.logLines))
	copy(lines, d.logLines)
	d.mu.Unlock()

	d.logBox.Clear()
	for _, line := range lines {
		colored := line
		switch {
		case strings.Contains(line, "AUTH ACCEPTED"):
			colored = "[red]" + line + "[-]"
		case strings.Contains(line, "AUTH ATTEMPT"):
			colored = "[yellow]" + line + "[-]"
		case strings.Contains(line, "COMMAND"):
			colored = "[cyan]" + line + "[-]"
		case strings.Contains(line, "NEW CONNECTION"):
			colored = "[green]" + line + "[-]"
		case strings.Contains(line, "DISCONNECT"):
			colored = "[gray]" + line + "[-]"
		}
		fmt.Fprintln(d.logBox, colored)
	}
	d.logBox.ScrollToEnd()
}
