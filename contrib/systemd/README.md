# Systemd Examples

This directory contains example systemd service files and configurations for deploying the Herald application.

## Example: herald.service

The `herald.service` file is a systemd service unit that can be used to manage the Herald application as a background service. To use it:

1. Copy the service file to the systemd directory:

   ```bash
   sudo cp herald.service /etc/systemd/system/
   ```

2. Reload the systemd daemon to recognize the new service:

   ```bash
   sudo systemctl daemon-reload
   ```

3. Enable the service to start on boot:

   ```bash
   sudo systemctl enable herald
   ```

4. Start the service:

   ```bash
   sudo systemctl start herald
   ```

5. Check the service status:

   ```bash
   sudo systemctl status herald
   ```

### Adding Command-Line Arguments

You can customize the behavior of the Herald application by adding command-line arguments to the `ExecStart` line in the service file. For example:

```ini
[Service]
ExecStart=/usr/local/bin/herald --log-level debug --dry-run
```

In this example:

- `--log-level debug` sets the logging level to debug.
- `--dry-run` enables dry-run mode, where no changes are applied.

After modifying the service file, reload the systemd daemon and restart the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart herald
```
