[general]

# Secondary login Transformation rule
# ${LOGIN} will be replaced by login
# ${DOMAIN} (optional) will be replaced by domain if it exists.
# Empty value means no transformation rule.
transformation_rule = string(default="")

# Account Mapping password retriever
# Transformation to apply to find the correct account.
# ${USER} will be replaced by the user's login.
# ${DOMAIN} will be replaced by the user's domain (in case of LDAP mapping).
# ${USER_DOMAIN} will be replaced by the user's login + "@" + user's domain (or just user's login if there's no domain).
# ${GROUP} will be replaced by the authorization's user group.
# ${DEVICE} will be replaced by the device's name.
# A regular expression is allowed to transform a variable, with the syntax: ${USER:/regex/replacement}, groups can be captured with parentheses and used with \1, \2, ...
# For example to replace leading "A" by "B" in the username: ${USER:/^A/B}
# Empty value means no transformation rule.
vault_transformation_rule = string(default="")


[session]

# No automatic disconnection due to inactivity, timer is set on target session.
# If value is between 1 and 30, then 30 is used.
# If value is set to 0, then value set in "Base inactivity timeout" (in "RDP Proxy" configuration option) is used.<br/>
# (in seconds)
inactivity_timeout = integer(min=0, default=0)

[all_target_mod]

# This parameter allows you to specify max timeout before a TCP connection is aborted. If the option value is specified as 0, TCP will use the system default.<br/>
# (in milliseconds)
#_advanced
tcp_user_timeout = integer(min=0, max=3600000, default=0)

[rdp]

# This option should only be used if the server or client is showing graphical issues.
# In general, disabling RDP orders has a negative impact on performance.<br/>
# Disables supported drawing orders:
# &nbsp; &nbsp;    0: DstBlt
# &nbsp; &nbsp;    1: PatBlt
# &nbsp; &nbsp;    2: ScrBlt
# &nbsp; &nbsp;    3: MemBlt
# &nbsp; &nbsp;    4: Mem3Blt
# &nbsp; &nbsp;    9: LineTo
# &nbsp; &nbsp;   15: MultiDstBlt
# &nbsp; &nbsp;   16: MultiPatBlt
# &nbsp; &nbsp;   17: MultiScrBlt
# &nbsp; &nbsp;   18: MultiOpaqueRect
# &nbsp; &nbsp;   22: Polyline
# &nbsp; &nbsp;   25: EllipseSC
# &nbsp; &nbsp;   27: GlyphIndex<br/>
# (values are comma-separated)
#_advanced
disabled_orders = string(default="27")

# Enable NLA authentication in secondary target.
enable_nla = boolean(default=True)

# If enabled, NLA authentication will try Kerberos before NTLM.
# (if enable_nla is disabled, this value is ignored).
enable_kerberos = boolean(default=False)

# Minimal incoming TLS level 0=TLSv1, 1=TLSv1.1, 2=TLSv1.2, 3=TLSv1.3
tls_min_level = integer(min=0, default=0)

# Maximal incoming TLS level 0=no restriction, 1=TLSv1.1, 2=TLSv1.2, 3=TLSv1.3
tls_max_level = integer(min=0, default=0)

# TLSv1.2 additional ciphers supported by client, default is empty to apply system-wide configuration (SSL security level 2), ALL for support of all ciphers to ensure highest compatibility with target servers.
cipher_string = string(default="ALL")

# Show in the logs the common cipher list supported by client and server
#_advanced
show_common_cipher_list = boolean(default=False)

# List of (comma-separated) enabled dynamic virtual channel. If character '*' is used as a name then enables everything.
# An explicit name in 'Allowed dynamic channels' and 'Denied dynamic channels' will have higher priority than '*'.
#_advanced
allowed_dynamic_channels = string(default="*")

# List of (comma-separated) disabled dynamic virtual channel. If character '*' is used as a name then disables everything.
# An explicit name in 'Allowed dynamic channels' and 'Denied dynamic channels' will have higher priority than '*'.
#_advanced
denied_dynamic_channels = string(default="")

# The secondary target connection can be redirected to a specific session on another RDP server.
#_display_name=Enable Server Redirection Support
server_redirection = boolean(default=False)

# Load balancing information.
# For example 'tsv://MS Terminal Services Plugin.1.Sessions' where 'Sessions' is the name of the targeted RD Collection which works fine.
load_balance_info = string(default="")

# As far as possible, use client-provided initial program (Alternate Shell)
use_client_provided_alternate_shell = boolean(default=False)

# As far as possible, use client-provided remote program (RemoteApp)
use_client_provided_remoteapp = boolean(default=False)

# As far as possible, use native RemoteApp capability
use_native_remoteapp_capability = boolean(default=True)

# Adds RDPDR channel metadata to session logs. Disabling this option makes shared disks more responsive, but metadata will no longer be collected.if at least one authorization of RDPDR is missing (Printer, ComPort, SmartCard, Drive), then this option is considered enabled.
#_advanced
enable_rdpdr_data_analysis = boolean(default=True)

# Actives conversion of RemoteApp target session to desktop session.
# Otherwise, Alternate Shell will be used.
# Some Windows Shell features may be unavailable in one or both cases, and applications using them may behave differently.
#_display_name=Enable translated RemoteApp with AM
wabam_uses_translated_remoteapp = boolean(default=False)

# Enables support of the remoteFX codec.
enable_remotefx = boolean(default=False)

# Connect to the server in Restricted Admin mode.
# This mode must be supported by the server (available from Windows Server 2012 R2), otherwise, connection will fail.
# NLA must be enabled.
enable_restricted_admin_mode = boolean(default=False)

# NLA will be disabled.
# Target must be set for interactive login, otherwise server connection may not be guaranteed.
# Smartcard device must be available on client desktop.
# Smartcard redirection (Proxy option RDP_SMARTCARD) must be enabled on service.
force_smartcard_authentication = boolean(default=False)

# Enable target connection on ipv6
enable_ipv6 = boolean(default=True)

# Console mode management for targets on Windows Server 2003 (requested with /console or /admin mstsc option)
# &nbsp; &nbsp;   allow: Forward Console mode request from client to the target.
# &nbsp; &nbsp;   force: Force Console mode on target regardless of client request.
# &nbsp; &nbsp;   forbid: Block Console mode request from client.
#_display_name=Console mode
mode_console = option('allow', 'force', 'forbid', default="allow")

# Allows the proxy to automatically reconnect to secondary target when a network error occurs.
# The server must support reconnection cookie.
#_advanced
auto_reconnection_on_losing_target_link = boolean(default=False)

# ⚠ The use of this feature is not recommended!<br/>
# If the feature is enabled, the end user can trigger a session disconnection/reconnection with the shortcut Ctrl+F12.
# This feature should not be used together with the End disconnected session option (section session_probe).
# The keyboard shortcut is fixed and cannot be changed.
#_advanced
allow_session_reconnection_by_shortcut = boolean(default=False)

# The delay between a session disconnection and the automatic reconnection that follows.<br/>
# (in milliseconds)
#_advanced
session_reconnection_delay = integer(min=0, max=15000, default=0)

# Forward the build number advertised by the client to the server. If forwarding is disabled a default (static) build number will be sent to the server.
#_advanced
forward_client_build_number = boolean(default=True)

# To resolve the session freeze issue with Windows 7/Windows Server 2008 target.
bogus_monitor_layout_treatment = boolean(default=False)

# Account to be used for armoring Kerberos tickets. Must be in the form 'account_name@domain_name[@device_name]'. If account resolution succeeds the username and password associated with this account will be used; otherwise the below fallback username and password will be used instead.
#_advanced
krb_armoring_account = string(default="")

# Realm to be used for armoring Kerberos tickets.
#_advanced
krb_armoring_realm = string(default="")

# Fallback username to be used for armoring Kerberos tickets.
#_advanced
krb_armoring_fallback_user = string(default="")

# Fallback password to be used for armoring Kerberos tickets.
#_advanced
krb_armoring_fallback_password = string(default="")

# Delay before showing disconnect message after the last RemoteApp window is closed.<br/>
# (in milliseconds)
#_advanced
remote_programs_disconnect_message_delay = integer(min=3000, max=120000, default=3000)

# This option only has an effect in RemoteApp sessions (RDS meaning).
# If enabled, the RDP Proxy relies on the Session Probe to launch the remote programs.
# Otherwise, remote programs will be launched according to Remote Programs Virtual Channel Extension of Remote Desktop Protocol. This latter is the native method.
# The difference is that Session Probe does not start a new application when its host session is resumed. Conversely, launching applications according to Remote Programs Virtual Channel Extension of Remote Desktop Protocol is not affected by this behavior. However, launching applications via the native method requires them to be published in Remote Desktop Services, which is unnecessary if launched by the Session Probe.
use_session_probe_to_launch_remote_program = boolean(default=True)

# ⚠ The use of this feature is not recommended!<br/>
# Replace an empty mouse pointer with normal pointer.
#_advanced
replace_null_pointer_by_default_pointer = boolean(default=False)

[protocol]

# &nbsp; &nbsp;   0: Windows
# &nbsp; &nbsp;   1: Bastion, xrdp or others
#_advanced
save_session_info_pdu = option(0, 1, default=1)

[session_probe]

enable_session_probe = boolean(default=True)

# This parameter only has an effect in Desktop sessions.
# It allows you to choose between Smart launcher and Legacy launcher to launch the Session Probe.
# The Smart launcher and the Legacy launcher do not have the same technical prerequisites. Detailed information can be found in the Administration guide.
use_smart_launcher = boolean(default=True)

# This parameter enables or disables the Session Probe’s launch mask.
# The Launch mask hides the Session Probe launch steps from the end-users.
# Disabling the mask makes it easier to diagnose Session Probe launch issues. It is recommended to enable the mask for normal operation.
#_advanced
enable_launch_mask = boolean(default=True)

# It is recommended to use option 1 (disconnect user).
# &nbsp; &nbsp;   0: The metadata collected is not essential for us. Instead, we prefer to minimize the impact on the user experience. The Session Probe launch will be in best-effort mode. The prevailing duration is defined by the 'Launch fallback timeout' instead of the 'Launch timeout'.
# &nbsp; &nbsp;   1: This is the recommended setting. If the target meets all the technical prerequisites, there is no reason for the Session Probe not to launch. All that remains is to adapt the value of 'Launch timeout' to the performance of the target.
# &nbsp; &nbsp;   2: We wish to be able to recover the behavior of Bastion 5 when the Session Probe does not launch. The prevailing duration is defined by the 'Launch fallback timeout' instead of the 'Launch timeout'.
on_launch_failure = option(0, 1, 2, default=1)

# This parameter is used if 'On launch failure' is 1 (disconnect user).
# 0 to disable timeout.<br/>
# (in milliseconds)
#_advanced
launch_timeout = integer(min=0, max=300000, default=40000)

# This parameter is used if 'On launch failure' is 0 (ignore failure and continue) or 2 (retry without Session Probe).
# 0 to disable timeout.<br/>
# (in milliseconds)
#_advanced
launch_fallback_timeout = integer(min=0, max=300000, default=40000)

# If enabled, the Launch timeout countdown timer will be started only after user logged in Windows. Otherwise, the countdown timer will be started immediately after RDP protocol connexion.
start_launch_timeout_timer_only_after_logon = boolean(default=True)

# The amount of time that RDP Proxy waits for a reply from the Session Probe to the KeepAlive message before adopting the behavior defined by 'On keepalive timeout'.
# If our local network is subject to congestion, or if the Windows lacks responsiveness, it is possible to increase the value of the timeout to minimize disturbances related to the behavior defined by 'On keepalive timeout'.
# The KeepAlive message is used to detect Session Probe unavailability. Without Session Probe, session monitoring will be minimal. No metadata will be collected.
# During the delay between sending a KeepAlive request and receiving the corresponding reply, Session Probe availability is indeterminate.<br/>
# (in milliseconds)
#_advanced
keepalive_timeout = integer(min=0, max=60000, default=5000)

# This parameter allows us to choose the behavior of the RDP Proxy in case of losing the connection with Session Probe.
# &nbsp; &nbsp;   0: Designed to minimize the impact on the user experience if the Session Probe is unstable. It should not be used when Session Probe is working well. An attacker can take advantage of this setting by simulating a Session Probe crash in order to bypass the surveillance.
# &nbsp; &nbsp;   1: Legacy behavior. It’s a choice that gives more security, but the impact on the user experience seems disproportionate. The RDP session can be closed (resulting in the permanent loss of all its unsaved elements) if the 'End disconnected session' parameter (or an equivalent setting at the RDS-level) is enabled.
# &nbsp; &nbsp;   2: This is the recommended setting. User actions will be blocked until contact with the Session Probe (reply to KeepAlive message or something else) is resumed.
on_keepalive_timeout = option(0, 1, 2, default=2)

# The behavior of this parameter is different between the Desktop session and the RemoteApp session (RDS meaning). But in each case, the purpose of enabling this parameter is to not leave disconnected sessions in a state unusable by the RDP proxy.
# If enabled, Session Probe will automatically end the disconnected Desktop session. Otherwise, the RDP session and the applications it contains will remain active after user disconnection (unless a parameter defined at the RDS-level decides otherwise).
# The parameter in RemoteApp session (RDS meaning) does not cause the latter to be closed but a simple cleanup. However, this makes the session suitable for reuse.
# This parameter must be enabled for Web applications because an existing session with a running browser cannot be reused.
# It is also recommended to enable this parameter for connections in RemoteApp mode (RDS meaning) when 'Use session probe to launch remote program' parameter is enabled. Because an existing Session Probe does not launch a startup program (a new Bastion application) when the RemoteApp session resumes.
end_disconnected_session = boolean(default=False)

# If enabled, disconnected auto-deployed Application Driver session will automatically terminate by Session Probe.
enable_autodeployed_appdriver_affinity = boolean(default=True)

# This parameter allows you to enable the Windows-side logging of Session Probe.
# The generated files are located in the Windows user's temporary directory. These files can only be analyzed by the WALLIX team.
#_advanced
enable_log = boolean(default=False)

# This parameter enables or disables the Log files rotation for Windows-side logging of Session Probe.
# The Log files rotation helps reduce disk space consumption caused by logging. But the interesting information may be lost if the corresponding file is not retrieved in time.
#_advanced
enable_log_rotation = boolean(default=False)

# Defines logging severity levels.
# &nbsp; &nbsp;   1: The Fatal level designates very severe error events that will presumably lead the application to abort.
# &nbsp; &nbsp;   2: The Error level designates error events that might still allow the application to continue running.
# &nbsp; &nbsp;   3: The Info level designates informational messages that highlight the progress of the application at coarse-grained level.
# &nbsp; &nbsp;   4: The Warning level designates potentially harmful situations.
# &nbsp; &nbsp;   5: The Debug level designates fine-grained informational events that are mostly useful to debug an application.
# &nbsp; &nbsp;   6: The Detail level designates finer-grained informational events than Debug.
#_advanced
log_level = option(1, 2, 3, 4, 5, 6, default=5)

# (Deprecated!)
# The period above which the disconnected Application session will be automatically closed by the Session Probe.
# 0 to disable timeout.<br/>
# (in milliseconds)
#_advanced
disconnected_application_limit = integer(min=0, max=172800000, default=0)

# The period above which the disconnected Desktop session will be automatically closed by the Session Probe.
# 0 to disable timeout.<br/>
# (in milliseconds)
#_advanced
disconnected_session_limit = integer(min=0, max=172800000, default=0)

# The period of user inactivity above which the session will be locked by the Session Probe.
# 0 to disable timeout.<br/>
# (in milliseconds)
#_advanced
idle_session_limit = integer(min=0, max=172800000, default=0)

# The additional period given to the device to make Clipboard redirection available.
# This parameter is effective only if the Smart launcher is used.
# If we see the message "Clipboard Virtual Channel is unavailable" in the Bastion’s syslog and we are sure that this virtual channel is allowed on the device (confirmed by a direct connection test for example), we probably need to use this parameter.<br/>
# (in milliseconds)
#_advanced
smart_launcher_clipboard_initialization_delay = integer(min=0, default=2000)

# For under-performing devices.
# The extra time given to the device before starting the Session Probe launch sequence.
# This parameter is effective only if the Smart launcher is used.
# This parameter can be useful when (with Launch mask disabled) Windows Explorer is not immediately visible when the RDP session is opened.<br/>
# (in milliseconds)
#_advanced
smart_launcher_start_delay = integer(min=0, default=0)

# The delay between two simulated keystrokes during the Session Probe launch sequence execution.
# This parameter is effective only if the Smart launcher is used.
# This parameter may help if the Session Probe launch failure is caused by network slowness or device under-performance.
# This parameter is usually used together with the 'Smart launcher short delay' parameter.<br/>
# (in milliseconds)
#_advanced
smart_launcher_long_delay = integer(min=0, default=500)

# The delay between two steps of the same simulated keystrokes during the Session Probe launch sequence execution.
# This parameter is effective only if the Smart launcher is used.
# This parameter may help if the Session Probe launch failure is caused by network slowness or device under-performance.
# This parameter is usually used together with the 'Smart launcher long delay' parameter.<br/>
# (in milliseconds)
#_advanced
smart_launcher_short_delay = integer(min=0, default=50)

# Allow sufficient time for the RDP client (Access Manager) to respond to the Clipboard virtual channel initialization message. Otherwise, the time granted to the RDP client (Access Manager or another) for Clipboard virtual channel initialization will be defined by the 'Smart launcher clipboard initialization delay' parameter.
# This parameter is effective only if the Smart launcher is used and the RDP client is Access Manager.
#_advanced
#_display_name=Enable Smart launcher with AM affinity
smart_launcher_enable_wabam_affinity = boolean(default=True)

# The time interval between the detection of an error (example: a refusal by the target of the redirected drive) and the actual abandonment of the Session Probe launch.
# The purpose of this parameter is to give the target time to gracefully stop some ongoing processing.
# It is strongly recommended to keep the default value of this parameter.<br/>
# (in milliseconds)
#_advanced
launcher_abort_delay = integer(min=0, max=300000, default=2000)

# This parameter enables or disables the crash dump generation when the Session Probe encounters a fatal error.
# The crash dump file is useful for post-modem debugging. It is not designed for normal use.
# The generated files are located in the Windows user's temporary directory. These files can only be analyzed by the WALLIX team.
# There is no rotation mechanism to limit the number of dump files produced. Extended activation of this parameter can quickly exhaust disk space.
#_advanced
enable_crash_dump = boolean(default=False)

# Use only if you see unusually high consumption of system object handles by the Session Probe.
# The Session Probe will sabotage and then restart it-self if it consumes more handles than what is defined by this parameter.
# A value of 0 disables this feature.
# This feature can cause the session to be disconnected if the value of the 'On KeepAlive timeout' parameter is set to 1 (Disconnect user).
# If 'Allow multiple handshakes' parameter ('session_probe' section of 'Configuration options') is disabled, restarting the Session Probe will cause the session to disconnect.
#_advanced
handle_usage_limit = integer(min=0, max=1000, default=0)

# Use only if you see unusually high consumption of memory by the Session Probe.
# The Session Probe will sabotage and then restart it-self if it consumes more memory than what is defined by this parameter.
# A value of 0 disables this feature.
# This feature can cause the session to be disconnected if the value of the 'On KeepAlive timeout' parameter is set to 1 (Disconnect user).
# If 'Allow multiple handshakes' parameter ('session_probe' section of 'Configuration options') is disabled, restarting the Session Probe will cause the session to disconnect.
#_advanced
memory_usage_limit = integer(min=0, max=200000000, default=0)

# This debugging feature was created to determine the cause of high CPU consumption by Session Probe in certain environments.
# As a percentage, the effective alarm threshold is calculated in relation to the reference consumption determined at the start of the program execution. The alarm is deactivated if this value of parameter is less than 200 (200%% of reference consumption).
# When CPU consumption exceeds the allowed limit, debugging information can be collected (if the Windows-side logging is enabled), then Session Probe will sabotage. Additional behavior is defined by 'Cpu usage alarm action' parameter.
#_advanced
cpu_usage_alarm_threshold = integer(min=0, max=10000, default=0)

# Additional behavior when CPU consumption exceeds what is allowed. Please refer to the 'Cpu usage alarm threshold' parameter.
# &nbsp; &nbsp;   0: Restart the Session Probe. May result in session disconnection due to loss of KeepAlive messages! Please refer to 'On keepalive timeout' parameter of current section and 'Allow multiple handshakes' parameter of 'Configuration options'.
# &nbsp; &nbsp;   1: Stop the Session Probe. May result in session disconnection due to loss of KeepAlive messages! Please refer to 'On keepalive timeout' parameter of current section.
#_advanced
cpu_usage_alarm_action = option(0, 1, default=0)

# For application session only.
# The delay between the launch of the application and the start of End of session check.
# Sometimes an application takes a long time to create its window. If the End of session check is start too early, the Session Probe may mistakenly conclude that there is no longer any active process in the session. And without active processes, the application session will be logged off by the Session Probe.
# 'End of session check delay time' allow you to delay the start of End of session check in order to give the application the time to create its window.<br/>
# (in milliseconds)
#_advanced
end_of_session_check_delay_time = integer(min=0, max=60000, default=0)

# For application session only.
# If enabled, during the End of session check, the processes that do not have a visible window will not be counted as active processes of the session. Without active processes, the application session will be logged off by the Session Probe.
#_advanced
ignore_ui_less_processes_during_end_of_session_check = boolean(default=True)

# This parameter is used to provide the list of (comma-separated) system processes that can be run in the session.
# Ex.: dllhos.exe,TSTheme.exe
# Unlike user processes, system processes do not keep the session open. A session with no user process will be automatically closed by Session Probe after starting the End of session check.
extra_system_processes = string(default="")

# This parameter concerns the functionality of the Password field detection performed by the Session Probe. This detection is necessary to avoid logging the text entered in the password fields as metadata of session (also known as Session log).
# Unfortunately, the detection does not work with applications developed in Java, Flash, etc. In order to work around the problem, we will treat the windows of these applications as input fields of unknown type. Therefore, the text entered in these will not be included in the session’s metadata.
# One of the specifics of these applications is that their main windows do not have any child window from point of view of WIN32 API. Activating this parameter allows this property to be used to detect applications developed in Java or Flash.
# Please refer to the 'Keyboard input masking level' parameter of 'session_log' section.
#_advanced
childless_window_as_unidentified_input_field = boolean(default=True)

# Comma-separated process names. (Ex.: chrome.exe,ngf.exe)
# This parameter concerns the functionality of the Password field detection performed by the Session Probe. This detection is necessary to avoid logging the text entered in the password fields as metadata of session (also known as Session log).
# Unfortunately, the detection is not infallible. In order to work around the problem, we will treat the windows of these applications as input fields of unknown type. Therefore, the text entered in these will not be included in the session’s metadata.
# This parameter is used to provide the list of processes whose windows are considered as input fields of unknown type.
# Please refer to the 'Keyboard input masking level' parameter of 'session_log' section.
windows_of_these_applications_as_unidentified_input_field = string(default="")

# This parameter is used when resuming a session hosting a existing Session Probe.
# If enabled, the Session Probe will activate or deactivate features according to the value of 'Disabled features' parameter received when resuming its host session. Otherwise, the Session Probe will keep the same set of features that were used during the previous connection.
# It is recommended to keep the default value of this parameter.
#_advanced
update_disabled_features = boolean(default=True)

# This parameter was created to work around some compatibility issues and to limit the CPU load that the Session Probe process causes.
# If 'Java Acccess Bridge' feature is disabled, data entered in the password field of Java applications may be visible in the metadata. For more information please refer to 'Keyboard input masking level' parameter of 'session_log' section. For more information please also refer to 'Childless window as unidentified input field and Windows of these applications as unidentified input field oIt is not recommended to deactivate 'MS Active Accessibility' and 'MS UI Automation' at the same time. This configuration will lead to the loss of detection of password input fields. Entries in these fields will be visible as plain text in the session metadata. For more information please refer to 'Keyboard input masking level' parameter of 'session_log' section of 'Connection Policy'.
# &nbsp; &nbsp;   0x000: none
# &nbsp; &nbsp;   0x001: disable Java Access Bridge. General user activity monitoring in the Java applications (including detection of password fields).
# &nbsp; &nbsp;   0x002: disable MS Active Accessbility. General user activity monitoring (including detection of password fields). (legacy API)
# &nbsp; &nbsp;   0x004: disable MS UI Automation. General user activity monitoring (including detection of password fields). (new API)
# &nbsp; &nbsp;   0x010: disable Inspect Edge location URL. Basic web navigation monitoring.
# &nbsp; &nbsp;   0x020: disable Inspect Chrome Address/Search bar. Basic web navigation monitoring.
# &nbsp; &nbsp;   0x040: disable Inspect Firefox Address/Search bar. Basic web navigation monitoring.
# &nbsp; &nbsp;   0x080: disable Monitor Internet Explorer event. Advanced web navigation monitoring.
# &nbsp; &nbsp;   0x100: disable Inspect group membership of user. User identity monitoring.<br/>
# Note: values can be added (disable all: 0x1 + 0x2 + 0x4 + 0x10 + 0x20 + 0x40 + 0x80 + 0x100 = 0x1f7)
#_advanced
#_hex
disabled_features = integer(min=0, max=511, default=352)

# This parameter has no effect on the device without BestSafe.
# Is enabled, Session Probe relies on BestSafe to perform the detection of application launches and the detection of outgoing connections.
# BestSafe has more efficient mechanisms in these tasks than Session Probe.
# For more information please refer to 'Outbound connection monitoring rules' parameter and 'Process monitoring rules' parameter.
enable_bestsafe_interaction = boolean(default=False)

# This parameter has no effect on the device without BestSafe.
# BestSafe interaction must be enabled. Please refer to 'Enable bestsafe interaction' parameter.
# This parameter allows you to choose the behavior of the RDP Proxy in case of detection of Windows account manipulation.
# Detectable account manipulations are the creation, deletion of a Windows account, and the addition and deletion of an account from a Windows user group.
# &nbsp; &nbsp;   0: User action will be accepted
# &nbsp; &nbsp;   1: (Same thing as 'allow') 
# &nbsp; &nbsp;   2: User action will be rejected
on_account_manipulation = option(0, 1, 2, default=0)

# This parameter is used to indicate the name of an environment variable, to be set on the Windows device, and pointed to a directory (on the device) that can be used to store and start the Session Probe. The environment variable must be available in the Windows user session.
# The environment variable name is limited to 3 characters or less.
# By default, the Session Probe will be stored and started from the temporary directory of Windows user.
# This parameter is useful if a GPO prevents Session Probe from starting from the Windows user's temporary directory.
#_advanced
alternate_directory_environment_variable = string(max=3, default="")

# If enabled, the session, once disconnected, can be resumed by another Bastion user.
# Except in special cases, this is usually a security problem.
# By default, a session can only be resumed by the Bastion user who created it.
public_session = boolean(default=False)

# This parameter is used to provide the list of (comma-separated) rules used to monitor outgoing connections created in the session.
# (Ex. IPv4 addresses: $deny:192.168.0.0/24:5900,$allow:192.168.0.110:21)
# (Ex. IPv6 addresses: $deny:2001:0db8:85a3:0000:0000:8a2e:0370:7334:3389,$allow:[20D1:0:3238:DFE1:63::FEFB]:21)
# (Ex. hostname can be used to resolve to both IPv4 and IPv6 addresses: $allow:host.domain.net:3389)
# (Ex. for backwards compatibility only: 10.1.0.0/16:22)
# BestSafe can be used to perform detection of outgoing connections created in the session. Please refer to 'Enable bestsafe interaction' parameter.
outbound_connection_monitoring_rules = string(default="")

# This parameter is used to provide the list of (comma-separated) rules used to monitor the execution of processes in the session.
# (Ex.: $deny:taskmgr.exe)
# @ = All child processes of (Bastion) application (Ex.: $deny:@)
# BestSafe can be used to perform detection of process launched in the session. Please refer to 'Enable bestsafe interaction' parameter.
process_monitoring_rules = string(default="")

# &nbsp; &nbsp;   0: Get command-line of processes via Windows Management Instrumentation. (Legacy method)
# &nbsp; &nbsp;   1: Calling internal system APIs to get the process command line. (More efficient but less stable)
# &nbsp; &nbsp;   2: First use internal system APIs call, if that fails, use Windows Management Instrumentation method.
#_advanced
process_command_line_retrieve_method = option(0, 1, 2, default=2)

# Time between two polling performed by Session Probe.
# The parameter is created to adapt the CPU consumption to the performance of the Windows device.
# The longer this interval, the less detailed the session metadata collection and the lower the CPU consumption.<br/>
# (in milliseconds)
#_advanced
periodic_task_run_interval = integer(min=300, max=2000, default=500)

# If enabled, Session Probe activity will be minimized when the user is disconnected from the session. No metadata will be collected during this time.
# The purpose of this behavior is to optimize CPU consumption.
#_advanced
pause_if_session_is_disconnected = boolean(default=False)

[server_cert]

# Keep known server certificates on Bastion
server_cert_store = boolean(default=True)

# Behavior of certificates check.
# &nbsp; &nbsp;   0: fails if certificates doesn't match or miss.
# &nbsp; &nbsp;   1: fails if certificate doesn't match, succeed if no known certificate.
# &nbsp; &nbsp;   2: succeed if certificates exists (not checked), fails if missing.
# &nbsp; &nbsp;   3: always succeed.
# System errors like FS access rights issues or certificate decode are always check errors leading to connection rejection.
server_cert_check = option(0, 1, 2, 3, default=1)

# Warn if check allow connexion to server.
# &nbsp; &nbsp;   0x0: nobody
# &nbsp; &nbsp;   0x1: message sent to syslog
# &nbsp; &nbsp;   0x2: User notified (through proxy interface)
# &nbsp; &nbsp;   0x4: admin notified (Bastion notification)<br/>
# Note: values can be added (enable all: 0x1 + 0x2 + 0x4 = 0x7)
#_advanced
#_hex
server_access_allowed_message = integer(min=0, max=7, default=1)

# Warn that new server certificate file was created.
# &nbsp; &nbsp;   0x0: nobody
# &nbsp; &nbsp;   0x1: message sent to syslog
# &nbsp; &nbsp;   0x2: User notified (through proxy interface)
# &nbsp; &nbsp;   0x4: admin notified (Bastion notification)<br/>
# Note: values can be added (enable all: 0x1 + 0x2 + 0x4 = 0x7)
#_advanced
#_hex
server_cert_create_message = integer(min=0, max=7, default=1)

# Warn that server certificate file was successfully checked.
# &nbsp; &nbsp;   0x0: nobody
# &nbsp; &nbsp;   0x1: message sent to syslog
# &nbsp; &nbsp;   0x2: User notified (through proxy interface)
# &nbsp; &nbsp;   0x4: admin notified (Bastion notification)<br/>
# Note: values can be added (enable all: 0x1 + 0x2 + 0x4 = 0x7)
#_advanced
#_hex
server_cert_success_message = integer(min=0, max=7, default=1)

# Warn that server certificate file checking failed.
# &nbsp; &nbsp;   0x0: nobody
# &nbsp; &nbsp;   0x1: message sent to syslog
# &nbsp; &nbsp;   0x2: User notified (through proxy interface)
# &nbsp; &nbsp;   0x4: admin notified (Bastion notification)<br/>
# Note: values can be added (enable all: 0x1 + 0x2 + 0x4 = 0x7)
#_advanced
#_hex
server_cert_failure_message = integer(min=0, max=7, default=1)

[session_log]

# Classification of input data is performed using Session Probe. Without the latter, all the texts entered are considered unidentified.
# &nbsp; &nbsp;   0: keyboard input are not masked
# &nbsp; &nbsp;   1: only passwords are masked
# &nbsp; &nbsp;   2: passwords and unidentified texts are masked
# &nbsp; &nbsp;   3: keyboard inputs are not logged
keyboard_input_masking_level = option(0, 1, 2, 3, default=2)

[video]

# Disable keyboard log:
# (Please see also "Keyboard input masking level" in "session_log" section of "Connection Policy".)
# &nbsp; &nbsp;   0x0: none
# &nbsp; &nbsp;   0x1: disable keyboard log in session log
# &nbsp; &nbsp;   0x2: disable keyboard log in recorded sessions<br/>
# Note: values can be added (disable all: 0x1 + 0x2 = 0x3)
#_advanced
#_hex
disable_keyboard_log = integer(min=0, max=3, default=0)

[file_verification]

# Enable use of ICAP service for file verification on upload.
enable_up = boolean(default=False)

# Enable use of ICAP service for file verification on download.
enable_down = boolean(default=False)

# Verify text data via clipboard from client to server.
# File verification on upload must be enabled via option Enable up.
clipboard_text_up = boolean(default=False)

# Verify text data via clipboard from server to client
# File verification on download must be enabled via option Enable down.
clipboard_text_down = boolean(default=False)

# Block file transfer from client to server on invalid file verification.
# File verification on upload must be enabled via option Enable up.
block_invalid_file_up = boolean(default=False)

# Block file transfer from server to client on invalid file verification.
# File verification on download must be enabled via option Enable down.
block_invalid_file_down = boolean(default=False)

# Log the files and clipboard texts that are verified and accepted. By default, only those rejected are logged.
#_advanced
log_if_accepted = boolean(default=True)

# ⚠ This value affects the RAM used by the session.<br/>
# If option Block invalid file (up or down) is enabled, automatically reject file with greater filesize.<br/>
# (in megabytes)
#_advanced
max_file_size_rejected = integer(min=0, default=256)

[file_storage]

# Enable storage of transferred files (via RDP Clipboard).
# ⚠ Saving files can take up a lot of disk space
# &nbsp; &nbsp;   never: Never store transferred files.
# &nbsp; &nbsp;   always: Always store transferred files.
# &nbsp; &nbsp;   on_invalid_verification: Transferred files are stored only if file verification is invalid. File verification by ICAP service must be enabled (in section file_verification).
store_file = option('never', 'always', 'on_invalid_verification', default="never")

