"""Terminal scan: full-color, step-by-step output of all 15 agents, with optional full JSON.

    python -m app.scan                 dataset (official data, or sample if none)
    python -m app.scan --sample        force the generated sample data
    python -m app.scan --input-only    analyze only data added on the Input page
    python -m app.scan --merge-input   dataset + input data together
    python -m app.scan --json          print the full JSON payload under every step
    python -m app.scan --delay 0.15    slow the output down for a live demo
    python -m app.scan --jsonl         machine-readable: one JSON event per line, no colors
    python -m app.scan --no-color      plain text (for log files)

Emails are never sent from the terminal scan. Threats are still written to the audit log.
"""
import argparse
import json
import os
import sys
import time
from types import SimpleNamespace

from app import config, notify, runner, store, trace


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.scan", description="IdentityShield terminal scan")
    p.add_argument("--sample", action="store_true")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--input-only", action="store_true")
    group.add_argument("--merge-input", action="store_true")
    p.add_argument("--json", action="store_true", help="show the full JSON payload of every step")
    p.add_argument("--jsonl", action="store_true", help="one raw JSON event per line")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--delay", type=float, default=0.0, help="seconds to pause after each line (demo pacing)")
    args = p.parse_args(argv)

    if os.name == "nt":
        os.system("")                     # enables ANSI colors in the Windows console
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    color = not args.no_color and not args.jsonl
    config.EMAIL_MODE = "off"             # no emails from the CLI (process may exit before a send finishes)
    store.init_db()
    notify.init_tables()

    def show(ev: dict) -> None:
        if args.jsonl:
            print(json.dumps(ev, ensure_ascii=False), flush=True)
        else:
            print(trace.render_ansi(ev, show_json=args.json, color=color), flush=True)
        if args.delay > 0:
            time.sleep(min(args.delay, 5.0))

    input_mode = "only" if args.input_only else ("merge" if args.merge_input else None)
    app = SimpleNamespace(state=SimpleNamespace(result=None, startup_error=""))
    trace.add_listener(show)
    try:
        runner.run_now(app, use_sample=True if args.sample else None, input_mode=input_mode)
    finally:
        trace.remove_listener(show)

    st = runner.status()
    run = trace.run_status()
    if args.jsonl:
        print(json.dumps({"summary": st, "run": run}, ensure_ascii=False, default=str), flush=True)
    else:
        ok = st["state"] == "done"
        head = "\x1b[1;32m SCAN COMPLETE \x1b[0m" if ok else "\x1b[1;37;41m SCAN FAILED \x1b[0m"
        if not color:
            head = " SCAN COMPLETE " if ok else " SCAN FAILED "
        print(f"\n{head}  alerts: {st.get('alerts')}  threats logged: {run.get('threats')}  "
              f"steps: {len(run.get('completed', []))}/{run.get('total_steps')}  time: {st.get('duration_ms')} ms"
              + (f"\n  {st.get('detail')}" if st.get("detail") else ""), flush=True)
    return 0 if st["state"] == "done" else 1


if __name__ == "__main__":
    sys.exit(main())
