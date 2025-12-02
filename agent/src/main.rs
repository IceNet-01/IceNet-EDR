use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod core;
mod monitors;
mod detection;
mod response;
mod communication;
mod config;

use crate::core::Agent;
use crate::config::Config;

#[derive(Parser, Debug)]
#[command(name = "icenet-agent")]
#[command(about = "IceNet EDR Agent - Endpoint Detection and Response", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Run as service/daemon
    #[arg(short, long)]
    service: bool,

    /// Install as system service
    #[arg(long)]
    install: bool,

    /// Uninstall system service
    #[arg(long)]
    uninstall: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("icenet_agent={},icenet_protocol=info,icenet_models=info", log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("IceNet EDR Agent v{}", env!("CARGO_PKG_VERSION"));

    // Handle service installation/uninstallation
    if args.install {
        return install_service().await;
    }
    if args.uninstall {
        return uninstall_service().await;
    }

    // Load configuration
    let config = match args.config {
        Some(path) => Config::from_file(&path)?,
        None => Config::default(),
    };

    info!("Agent ID: {}", config.agent.agent_id);
    info!("Server URL: {}", config.agent.server_url);

    // Create and run agent
    let agent = Agent::new(config).await?;

    // Run agent and handle shutdown gracefully
    tokio::select! {
        result = agent.run() => {
            if let Err(e) = result {
                error!("Agent error: {}", e);
                return Err(e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Agent shutting down");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn install_service() -> Result<()> {
    use std::ffi::OsString;
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::*;

    info!("Installing IceNet EDR Agent as Windows service");

    // Get current executable path
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_str().unwrap();

    // Open service control manager
    let scm = unsafe {
        OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_ALL_ACCESS,
        )?
    };

    // Create service
    let service_name: Vec<u16> = OsString::from("IceNetAgent")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let display_name: Vec<u16> = OsString::from("IceNet EDR Agent")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let binary_path: Vec<u16> = OsString::from(format!("\"{}\" --service", exe_path_str))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let service = unsafe {
        CreateServiceW(
            scm,
            PCWSTR::from_raw(service_name.as_ptr()),
            PCWSTR::from_raw(display_name.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR::from_raw(binary_path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )?
    };

    unsafe { CloseServiceHandle(service)? };
    unsafe { CloseServiceHandle(scm)? };

    info!("Service installed successfully");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn install_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        info!("Installing IceNet EDR Agent as systemd service");

        let service_content = r#"[Unit]
Description=IceNet EDR Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/icenet-agent --service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"#;

        std::fs::write("/etc/systemd/system/icenet-agent.service", service_content)?;

        // Reload systemd and enable service
        std::process::Command::new("systemctl")
            .args(&["daemon-reload"])
            .status()?;
        std::process::Command::new("systemctl")
            .args(&["enable", "icenet-agent"])
            .status()?;

        info!("Service installed successfully. Start with: systemctl start icenet-agent");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        info!("Installing IceNet EDR Agent as launchd service");

        let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.icenet.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/icenet-agent</string>
        <string>--service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"#;

        let home = std::env::var("HOME")?;
        let plist_path = format!("{}/Library/LaunchAgents/com.icenet.agent.plist", home);
        std::fs::write(&plist_path, plist_content)?;

        // Load service
        std::process::Command::new("launchctl")
            .args(&["load", &plist_path])
            .status()?;

        info!("Service installed successfully");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
async fn uninstall_service() -> Result<()> {
    use std::ffi::OsString;
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::*;

    info!("Uninstalling IceNet EDR Agent service");

    let scm = unsafe {
        OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_ALL_ACCESS,
        )?
    };

    let service_name: Vec<u16> = OsString::from("IceNetAgent")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let service = unsafe {
        OpenServiceW(
            scm,
            PCWSTR::from_raw(service_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        )?
    };

    unsafe { DeleteService(service)? };
    unsafe { CloseServiceHandle(service)? };
    unsafe { CloseServiceHandle(scm)? };

    info!("Service uninstalled successfully");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn uninstall_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        info!("Uninstalling IceNet EDR Agent service");

        std::process::Command::new("systemctl")
            .args(&["stop", "icenet-agent"])
            .status()?;
        std::process::Command::new("systemctl")
            .args(&["disable", "icenet-agent"])
            .status()?;

        std::fs::remove_file("/etc/systemd/system/icenet-agent.service")?;

        std::process::Command::new("systemctl")
            .args(&["daemon-reload"])
            .status()?;

        info!("Service uninstalled successfully");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        info!("Uninstalling IceNet EDR Agent service");

        let home = std::env::var("HOME")?;
        let plist_path = format!("{}/Library/LaunchAgents/com.icenet.agent.plist", home);

        std::process::Command::new("launchctl")
            .args(&["unload", &plist_path])
            .status()?;

        std::fs::remove_file(&plist_path)?;

        info!("Service uninstalled successfully");
        Ok(())
    }
}
