# Wapo Review v2 (Go) Cutover & Rollback Runbook

## Pre-Cutover Checklist
1. Build and verify the static ARM64 binary:
   ```bash
   PATH="/var/lib/t3-server/.local/go/bin:$PATH" CGO_ENABLED=0 go test -count=1 ./...
   PATH="/var/lib/t3-server/.local/go/bin:$PATH" CGO_ENABLED=0 go vet ./...
   PATH="/var/lib/t3-server/.local/go/bin:$PATH" CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/wapo-review ./cmd/wapo-review
   ./bin/wapo-review --version   # expects: v2-go
   ```
2. Verify `bin/wapo-review` is readable/executable by the service user (`chmod 0755 bin/wapo-review`).
3. Confirm `WAPO_REVIEW_CREDENTIALS_PATH` JSON includes `providers` (`openai` or `anthropic` protocol, `base_url`, `api_key`, `model`), `github_app_id`, `github_private_key_path`, and `github_webhook_secret`.
4. (Optional) To enable Hatchet durable DAG execution, start `deploy/compose.hatchet.yml` and set `ORCHESTRATOR_MODE=hatchet` + `HATCHET_CLIENT_TOKEN`. Otherwise `ORCHESTRATOR_MODE=local` runs the embedded pure-Go SQLite queue with zero external services.

## Zero-Downtime Cutover
1. Back up the current `/etc/systemd/system/wapo-review.service`.
2. Update `ExecStart` to `/var/lib/t3-server/projects/wapo-review/bin/wapo-review serve` with `Environment=WAPO_REVIEW_ADDR=127.0.0.1:8788`.
3. Reload and restart:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart wapo-review.service
   curl -fsS http://127.0.0.1:8788/health
   ```
   Expected response:
   ```json
   {"runner":"local","service":"Wapo Review","status":"ok","version":"v2-go"}
   ```

## Instant Rollback
If anything unexpected occurs, restore the backed-up systemd unit pointing to `legacy-python/` + `.venv/bin/python -m uvicorn ubuntu_service:app` and run:
```bash
sudo systemctl daemon-reload
sudo systemctl restart wapo-review.service
```
