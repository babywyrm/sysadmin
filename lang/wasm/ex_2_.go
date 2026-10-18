// https://gist.github.com/lazyhacker/29814991efd82fee79ff56b2e9433f71
//
//

var signal = make(chan int)

// cbQuit is a function that gets attached to browser event.
func cbQuit(e js.Value) {
	window := browser.GetWindow()
	window.Document.GetElementById("runButton").SetProperty("disabled", false)
	window.Document.GetElementById("quit").SetAttribute("disabled", true)
	signal <- 0
}

// keepalive waits for a specific value as a signal to quit.  Browsers still run
// javascript and wasm in a single thread so until the wasm module releases
// control, the entire browser window is blocked waiting for the module to
// finish.  It looks like that while waiting for the blocked channel, the
// browser window gets control back and can continue its event loop.
func keepalive() {
	for {
		m := <-signal
		if m == 0 {
			println("quit signal received")
			break
		}
	}
}

func main() {
	q := js.NewEventCallback(js.StopImmediatePropagation, cbQuit)
	defer q.Close()

	window := browser.GetWindow()

	// Disable the Run button so the module doesn't get executed again while it
	// is running.  If it runs while a previous instance is still running then
	// the browswer will give an error.
	window.Document.GetElementById("runButton").SetAttribute("disabled", true)

	// Attach a browser event to the quit button so it calls our Go code when
	// it is clicked.  Also enable the Quit button now that the module is running.
	window.Document.GetElementById("quit").AddEventListener(browser.EventClick, q)
	window.Document.GetElementById("quit").SetProperty("disabled", false)

	window.Alert("Triggered from Go WASM module")
	window.Console.Info("hello, browser console")

	canvas, err := window.Document.GetElementById("testcanvas").ToCanvas()
	if err != nil {
		window.Console.Warn(err.Error())
	}

	// Draw a cicule in the canvas.
	canvas.Clear()
	canvas.BeginPath()
	canvas.Arc(100, 75, 50, 0, 2*math.Pi, false)
	canvas.Stroke()

	// A Go routine that prints its counter to the canvas.
	canvas.Font("30px Arial")
	time.Sleep(5 * time.Second)
	go func() {
		for i := 0; i < 10; i++ {
			canvas.Clear()
			canvas.FillText(strconv.Itoa(i), 10, 50)
			time.Sleep(1 * time.Second) // sleep allows the browser to take control otherwise the whole UI gets frozen.
		}
		canvas.Clear()
		canvas.FillText("Stop counting!", 10, 50)
	}()
  
	window.Console.Info("Go routine running while this message is printed to the console.")

	keepalive()
}
