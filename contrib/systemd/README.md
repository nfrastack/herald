# Systemd Examples

This directory contains example systemd service files and configurations for deploying the ZT DNS Companion application.

## Example: container-dns-companion.service

The `container-dns-companion.service` file is a systemd service unit that can be used to manage the ZT DNS Companion application as a background service. To use it:

1. Copy the service file to the systemd directory:

   ```bash
   sudo cp container-dns-companion.service /etc/systemd/system/
   ```

2. Reload the systemd daemon to recognize the new service:

   ```bash
   sudo systemctl daemon-reload
   ```

3. Enable the service to start on boot:

   ```bash
   sudo systemctl enable container-dns-companion
   ```

4. Start the service:

   ```bash
   sudo systemctl start container-dns-companion
   ```

5. Check the service status:

   ```bash
   sudo systemctl status container-dns-companion
   ```

### Adding Command-Line Arguments

You can customize the behavior of the ZT DNS Companion application by adding command-line arguments to the `ExecStart` line in the service file. For example:

```ini
[Service]
ExecStart=/usr/local/bin/container-dns-companion --log-level debug --dry-run
```

In this example:

- `--log-level debug` sets the logging level to debug.
- `--dry-run` enables dry-run mode, where no changes are applied.

After modifying the service file, reload the systemd daemon and restart the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart container-dns-companion
```

## Example: Using <container-dns-companion@.service>

The `container-dns-companion@.service` file allows the ZeroTier DNS Companion to be triggered for individual network interfaces. This is useful when you want to run the service specifically for a particular interface.

### How to Use

1. Copy the `container-dns-companion@.service` file to `/etc/systemd/system/`:

   ```bash
   sudo cp container-dns-companion@.service /etc/systemd/system/
   ```

2. Reload the systemd daemon to recognize the new service:

   ```bash
   sudo systemctl daemon-reload
   ```

3. Enable and start the service for a specific interface (replace `<interface>` with the actual interface name, e.g., `zt12345678`):

   ```bash
   sudo systemctl enable container-dns-companion@<interface>
   sudo systemctl start container-dns-companion@<interface>
   ```

### Example

To run the service for the `zt12345678` interface:

```bash
sudo systemctl enable container-dns-companion@zt12345678
sudo systemctl start container-dns-companion@zt12345678
```

This will pass the `-interface zt12345678` flag to the `container-dns-companion` application, ensuring it operates specifically for the `zt12345678` interface.

### Using Profiles for Configuration

Both `container-dns-companion.service` and `container-dns-companion@.service` support the use of profiles to simplify configuration management. Profiles allow you to define specific settings in configuration files, avoiding the need to pass multiple arguments directly to the service.

#### How to Use Profiles

1. Update the configuration to support profiles with the desired settings.

2. Modify the `ExecStart` line in the service file to include the `-profile` flag:

   ```ini
   [Service]
   ExecStart=/usr/bin/container-dns-companion -profile my-profile
   ```

3. For `container-dns-companion@.service`, you can combine the `-interface` flag with the `-profile` flag:

   ```ini
   [Service]
   ExecStart=/usr/bin/container-dns-companion -interface %i -profile my-profile
   ```

4. Reload the systemd daemon and restart the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart container-dns-companion
   ```