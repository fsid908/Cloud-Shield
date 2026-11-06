import { createElement, useEffect, useMemo, useRef, useState } from "react";

import AuthPage from "./components/AuthPage";

import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Check,
  ChevronDown,
  CircleHelp,
  Cloud,
  Database,
  File,
  FileClock,
  FileSearch,
  Files,
  HardDrive,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Siren,
  UploadCloud,
  X,
  LogOut,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import "./App.css";

const navigation = [
  { label: "Overview", icon: LayoutDashboard },

  { label: "Threat detection", icon: ShieldAlert, count: "07" },

  { label: "Incidents", icon: Siren, count: "02" },

  { label: "Protected files", icon: Files },

  { label: "Backup management", icon: Database },

  { label: "Recovery center", icon: RefreshCw },
];

const secondaryNavigation = [
  { label: "Analytics & reports", icon: Activity },

  { label: "Audit logs", icon: FileClock },

  { label: "Settings", icon: Settings },
];

const pageTitles = {
  Overview: [
    "Security overview",

    "Monitor your cloud environment and recovery readiness.",
  ],

  "Threat detection": [
    "Threat detection",

    "Review suspicious activity and detection events.",
  ],

  Incidents: [
    "Incident management",

    "Investigate security incidents and affected assets.",
  ],

  "Protected files": [
    "Protected files",

    "Review monitored files and their protection status.",
  ],

  "Backup management": [
    "Backup management",

    "Monitor backup jobs, storage and verification.",
  ],

  "Recovery center": [
    "Recovery center",

    "Review recovery points and restoration readiness.",
  ],

  "Analytics & reports": [
    "Analytics & reports",

    "Explore security and backup performance.",
  ],

  "Audit logs": [
    "Audit logs",

    "Review recorded security and administrative events.",
  ],

  Settings: [
    "Settings",

    "Manage your workspace preferences and configuration.",
  ],
};

function Badge({ children, tone = "neutral" }) {
  return (
    <span className={`badge badge-${tone}`}>
      <span className="badge-dot" />

      {children}
    </span>
  );
}

function MetricCard({ metric }) {
  const Icon = metric.icon;

  return (
    <article className="metric-card">
      <div className="metric-top">
        <span className="metric-label">{metric.label}</span>

        <span className={`metric-icon metric-icon-${metric.color}`}>
          <Icon size={18} />
        </span>
      </div>

      <div className="metric-value">{metric.value}</div>

      <div className="metric-foot">
        <span className={`metric-change change-${metric.trend}`}>
          {metric.trend === "up" && <ArrowUpRight size={14} />}

          {metric.trend === "down" && <ArrowDownRight size={14} />}

          {metric.change}
        </span>

        <span className="metric-note">{metric.note}</span>
      </div>
    </article>
  );
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const [authLoading, setAuthLoading] = useState(true);

  const [user, setUser] = useState(null);

  const [dashboardData, setDashboardData] = useState(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState("");
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showEditProfile, setShowEditProfile] = useState(false);
  const [editFullName, setEditFullName] = useState("");
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileError, setProfileError] = useState("");

  useEffect(() => {
    let isMounted = true;

    const checkAuthentication = async () => {
      try {
        const response = await fetch(
          `${import.meta.env.VITE_API_URL || "http://localhost:5000/api"}/auth/me`,

          { credentials: "include" },
        );

        const result = await response.json();

        if (!response.ok || !result.success) {
          throw new Error("Authentication required");
        }

        if (isMounted) {
          setUser(result.data?.user ?? result.data);

          setIsAuthenticated(true);
        }
      } catch {
        if (isMounted) {
          setUser(null);

          setIsAuthenticated(false);
        }
      } finally {
        if (isMounted) setAuthLoading(false);
      }
    };

    checkAuthentication();

    return () => {
      isMounted = false;
    };
  }, []);

  const fetchDashboardData = async (signal) => {
    setDashboardLoading(true);
    setDashboardError("");

    const base = import.meta.env.VITE_API_URL || "http://localhost:5000/api";
    try {
      const [activityResponse, detectionResponse, eventsResponse] =
        await Promise.all([
          fetch(`${base}/security/activity`, {
            credentials: "include",
            signal,
          }),
          fetch(`${base}/security/detection`, {
            credentials: "include",
            signal,
          }),
          fetch(`${base}/security/events`, {
            credentials: "include",
            signal,
          }),
        ]);

      const [activity, detection, events] = await Promise.all([
        activityResponse.json(),
        detectionResponse.json(),
        eventsResponse.json(),
      ]);

      if (!activityResponse.ok || !activity.success) {
        throw new Error(activity.message || "Failed to load activity.");
      }

      if (!detectionResponse.ok || !detection.success) {
        throw new Error(detection.message || "Failed to load detection data.");
      }

      if (!eventsResponse.ok || !events.success) {
        throw new Error(events.message || "Failed to load security events.");
      }
      setDashboardData({
        activity: activity.data,
        detection: detection.data,
        events: events.data?.events ?? [],
      });
    } catch (error) {
      if (error.name !== "AbortError") {
        setDashboardError(error.message);
      }
    } finally {
      if (!signal?.aborted) {
        setDashboardLoading(false);
      }
    }

  };

  useEffect(() => {
    if (!isAuthenticated) return;

    const controller = new AbortController();

    fetchDashboardData(controller.signal);

    return () => controller.abort();
  }, [isAuthenticated]);

  const handleLogout = async () => {
    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL || "http://localhost:5000/api"}/auth/logout`,

        {
          method: "POST",

          credentials: "include",
        },
      );

      if (!response.ok) {
        throw new Error("Logout failed");
      }

      setUser(null);

      setIsAuthenticated(false);

      setShowProfileMenu(false);
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  const [activePage, setActivePage] = useState("Overview");

  const [search, setSearch] = useState("");

  const [showNotifications, setShowNotifications] = useState(false);

  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [toast, setToast] = useState("");

  const [showWorkspaceMenu, setShowWorkspaceMenu] = useState(false);

  const [activeWorkspace, setActiveWorkspace] = useState(
    "Personal environment",
  );

  // File upload preview state

  const fileInputRef = useRef(null);

  const [selectedFile, setSelectedFile] = useState(null);

  const [isDragging, setIsDragging] = useState(false);

  const [uploadMessage, setUploadMessage] = useState(
    "Upload UI ready — secure file scanning is available.",
  );

  const [scanStatus, setScanStatus] = useState("idle");

  const [scanProgress, setScanProgress] = useState(0);

  const [scanResult, setScanResult] = useState(null);

  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

  const ALLOWED_EXTENSIONS = [
    ".pdf",

    ".doc",

    ".docx",

    ".xls",

    ".xlsx",

    ".ppt",

    ".pptx",

    ".txt",

    ".csv",

    ".jpg",

    ".jpeg",

    ".png",

    ".zip",
  ];

  const handleFileSelect = (file) => {
    if (!file) return;

    const fileName = file.name.toLowerCase();

    const isAllowedType = ALLOWED_EXTENSIONS.some((extension) =>
      fileName.endsWith(extension),
    );

    if (!isAllowedType) {
      setUploadMessage("Invalid file type. Please select a supported file.");

      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      setUploadMessage("File is too large. Maximum allowed size is 10 MB.");

      return;
    }

    if (file.size === 0) {
      setUploadMessage("Empty files cannot be selected.");

      return;
    }

    setSelectedFile(file);

    setUploadMessage(`${file.name} selected successfully. Ready for scanning.`);
  };

  const handleDrop = (event) => {
    event.preventDefault();

    setIsDragging(false);

    handleFileSelect(event.dataTransfer.files?.[0]);
  };

  const handleScan = async () => {
    if (!selectedFile || scanStatus === "scanning") return;

    setScanStatus("scanning");

    setScanProgress(0);

    setScanResult(null);

    setUploadMessage("Uploading file securely to Cloud-Shield...");

    try {
      const formData = new FormData();

      formData.append("file", selectedFile);

      const response = await fetch(
        `${import.meta.env.VITE_API_URL || "http://localhost:5000/api"}/files`,

        {
          method: "POST",

          credentials: "include",

          body: formData,
        },
      );

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.message || "File upload failed.");
      }

      const isQuarantined = result.data?.status === "quarantined";

      setScanProgress(100);
      setScanStatus("completed");

      setScanResult({
        message: result.message || "File uploaded successfully.",
        file: result.data,
      });

      setUploadMessage(
        isQuarantined
          ? `${selectedFile.name}: Malware detected! File has been quarantined.`
          : `${selectedFile.name} uploaded successfully. Backend file record created.`,
      );
    } catch (error) {
      setScanStatus("idle");

      setScanProgress(0);

      setScanResult(null);

      setUploadMessage(error.message || "Upload failed. Please try again.");
    }
  };

  const dashboardMetrics = [
    {
      label: "Recent activity",
      value: dashboardData?.activity?.totalEvents ?? "—",
      change: `${dashboardData?.activity?.riskLevel ?? "—"} risk`,
      note: `Last ${dashboardData?.activity?.windowSeconds ?? 30} seconds`,
      icon: Activity,
      color: "blue",
      trend: "neutral",
    },
    {
      label: "Files modified",
      value: dashboardData?.activity?.uniqueFilesModified ?? "—",
      change: "Recent activity",
      note: "Unique files modified",
      icon: Files,
      color: "teal",
      trend: "neutral",
    },
    {
      label: "Suspicious signals",
      value: dashboardData?.detection?.signalCount ?? "—",
      change: "Detection analysis",
      note: "Recent suspicious signals",
      icon: ShieldAlert,
      color: "amber",
      trend: "neutral",
    },
    {
      label: "Persisted events",
      value: dashboardData?.events?.length ?? "—",
      change: "Recorded events",
      note: "Saved security events",
      icon: AlertTriangle,
      color: "red",
      trend: "neutral",
    },
  ];
  const events = (dashboardData?.events ?? []).map((event) => {
    const riskScore = Number(event.riskScore ?? 0);

    const color =
      riskScore >= 70 ? "red" : riskScore >= 40 ? "amber" : "teal";

    const severity =
      riskScore >= 70 ? "High" : riskScore >= 40 ? "Medium" : "Low";

    const timestamp = event.createdAt ?? event.updatedAt;

    return {
      title: event.reason || event.detectionType || event.eventType || "Security event",
      asset:
        event.fileId?.originalName ||
        event.fileId?.storedName ||
        "Unknown file",
      time: timestamp ? new Date(timestamp).toLocaleString() : "—",
      severity,
      status: event.eventType === "suspicious_activity"
        ? "Threat detected"
        : "Recorded",
      color,
    };
  });

  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) return events;

    return events.filter((event) =>
      `${event.title} ${event.asset} ${event.severity} ${event.status}`

        .toLowerCase()

        .includes(query),
    );
  }, [search, events]);

  const selectPage = (label) => {
    setActivePage(label);

    setSidebarOpen(false);

    setShowNotifications(false);
  };

  const notify = (message) => {
    setToast(message);

    window.setTimeout(() => setToast(""), 3000);
  };

  const handleUpdateProfile = async (event) => {
    event.preventDefault();

    const fullName = editFullName.trim();

    if (!fullName) {
      setProfileError("Full name is required.");
      return;
    }

    setProfileSaving(true);
    setProfileError("");

    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL || "http://localhost:5000/api"}/auth/update-profile`,
        {
          method: "PUT",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ fullName }),
        },
      );

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.message || "Profile update failed.");
      }

      const updatedUser = result.data?.user ?? result.data;
      setUser(updatedUser);
      setShowEditProfile(false);
      notify("Profile updated successfully.");
    } catch (error) {
      setProfileError(error.message || "Unable to update profile.");
    } finally {
      setProfileSaving(false);
    }
  };
  const [pageTitle, pageDescription] =
    pageTitles[activePage] ?? pageTitles.Overview;

  const currentPage = activePage;

  if (authLoading) {
    return (
      <div className="auth-page">
        <p>Checking authentication...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <AuthPage
        onLogin={async () => {
          const response = await fetch(
            `${import.meta.env.VITE_API_URL || "http://localhost:5000/api"}/auth/me`,

            { credentials: "include" },
          );

          const result = await response.json();

          if (!response.ok || !result.success) {
            throw new Error(result.message || "Unable to load account.");
          }

          setUser(result.data?.user ?? result.data);

          setIsAuthenticated(true);
        }}
      />
    );
  }

  return (
    <div className="app-shell">
      {sidebarOpen && (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <button
            type="button"
            className="brand-home"
            onClick={() => selectPage("Overview")}
            aria-label="Cloud Shield home"
          >
            <span className="brand-mark">
              <ShieldCheck size={23} strokeWidth={2.1} />
            </span>

            <span className="brand-copy">
              <span className="brand-name">
                cloud<span>shield</span>
              </span>

              <span className="brand-caption">CLOUD SECURITY PLATFORM</span>
            </span>
          </button>

          <button
            type="button"
            className="sidebar-close"
            aria-label="Close sidebar"
            onClick={() => setSidebarOpen(false)}
          >
            <X size={18} />
          </button>
        </div>

        <div className="workspace-wrap">
          <button
            type="button"
            className="workspace"
            aria-expanded={showWorkspaceMenu}
            aria-haspopup="true"
            onClick={() => setShowWorkspaceMenu((open) => !open)}
          >
            <div className="workspace-avatar">
              <Cloud size={17} />
            </div>

            <div className="workspace-copy">
              <span>Workspace</span>

              <strong>{activeWorkspace}</strong>
            </div>

            <ChevronDown size={15} className="workspace-chevron" />
          </button>

          {showWorkspaceMenu && (
            <div className="workspace-menu">
              <span className="workspace-menu-label">YOUR WORKSPACES</span>

              <button
                type="button"
                className="workspace-option"
                onClick={() => {
                  setActiveWorkspace("Personal environment");

                  setShowWorkspaceMenu(false);

                  notify("Personal environment selected.");
                }}
              >
                <Cloud size={17} />

                <span>Personal environment</span>

                {activeWorkspace === "Personal environment" && (
                  <Check size={16} />
                )}
              </button>

              <button
                type="button"
                className="workspace-option"
                onClick={() => {
                  setShowWorkspaceMenu(false);

                  notify(
                    "Creating additional workspaces requires backend support.",
                  );
                }}
              >
                <span className="workspace-add">+</span>

                <span>Add workspace</span>
              </button>
            </div>
          )}
        </div>

        <div className="sidebar-section-label">WORKSPACE</div>

        <nav className="sidebar-nav" aria-label="Main navigation">
          {navigation.map(({ label, icon: Icon, count }) => (
            <button
              type="button"
              key={label}
              className={`nav-item ${activePage === label ? "nav-item-active" : ""
                }`}
              onClick={() => selectPage(label)}
            >
              {createElement(Icon, { size: 18, strokeWidth: 1.8 })}

              <span>{label}</span>

              {count && (
                <span
                  className={`nav-count ${label === "Incidents" ? "nav-count-alert" : ""
                    }`}
                >
                  {count}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-section-label sidebar-section-spaced">
          MANAGEMENT
        </div>

        <nav className="sidebar-nav" aria-label="Management navigation">
          {secondaryNavigation.map(({ label, icon: Icon }) => (
            <button
              type="button"
              key={label}
              className={`nav-item ${activePage === label ? "nav-item-active" : ""
                }`}
              onClick={() => selectPage(label)}
            >
              {createElement(Icon, { size: 18, strokeWidth: 1.8 })}

              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-spacer" />

        <div className="sidebar-security">
          <div className="security-icon">
            <LockKeyhole size={17} />
          </div>

          <strong>Your data, protected.</strong>

          <p>
            Keep your recovery points verified and your cloud environment
            monitored.
          </p>

          <button type="button" onClick={() => selectPage("Recovery center")}>
            Review recovery <ArrowRight size={14} />
          </button>
        </div>

        <div className="profile-wrap">
          <button
            type="button"
            className="profile-card"
            aria-expanded={showProfileMenu}
            aria-haspopup="true"
            onClick={() => setShowProfileMenu((open) => !open)}
          >
            <div className="profile-avatar">
              {(user?.fullName || user?.name || "U")
                .trim()
                .charAt(0)
                .toUpperCase()}
            </div>
            <div className="profile-copy">
              <strong>
                {user?.fullName || user?.name || "Workspace admin"}
              </strong>
              <span>{user?.role || "Administrator"}</span>
            </div>
            <MoreHorizontal size={19} />
          </button>
          {showProfileMenu && (
            <div className="profile-menu">
              <div className="profile-menu-header">
                <div className="profile-menu-avatar">
                  {(user?.fullName || user?.name || "U")
                    .trim()
                    .charAt(0)
                    .toUpperCase()}
                </div>

                <div className="profile-menu-identity">
                  <strong>
                    {user?.fullName || user?.name || "Workspace admin"}
                  </strong>
                  <span>{user?.email || "Email not available"}</span>
                </div>
              </div>

              <div className="profile-menu-divider" />

              <div className="profile-menu-details">
                <span>ACCOUNT ROLE</span>
                <strong>{user?.role || "Administrator"}</strong>
              </div>
              <button
                type="button"
                className="profile-edit-button"
                onClick={() => {
                  setEditFullName(user?.fullName || user?.name || "");
                  setProfileError("");
                  setShowProfileMenu(false);
                  setShowEditProfile(true);
                }}
              >
                Edit Profile
              </button>
            </div>
          )}
        </div>

        <button type="button" className="nav-item" onClick={handleLogout}>
          <LogOut size={18} strokeWidth={1.8} />

          <span>Sign out</span>
        </button>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="mobile-menu icon-button"
              aria-label="Open navigation"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu size={20} />
            </button>

            <div className="breadcrumb">
              <span>Workspace</span>

              <span className="breadcrumb-separator">/</span>

              <strong>{activePage}</strong>
            </div>
          </div>

          <div className="topbar-right">
            <label className="global-search">
              <Search size={16} />

              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search events..."
                aria-label="Search security events"
              />

              <kbd>/</kbd>
            </label>

            <div className="notification-wrap">
              <button
                type="button"
                className="icon-button notification-button"
                aria-label="Notifications"
                onClick={() => setShowNotifications((value) => !value)}
              >
                <Bell size={19} />

                <span className="notification-dot" />
              </button>

              {showNotifications && (
                <div className="notification-popover">
                  <div className="popover-heading">
                    <strong>Notifications</strong>

                    <span>2 new</span>
                  </div>

                  <div className="notification-entry">
                    <span className="notification-symbol symbol-red">
                      <AlertTriangle size={16} />
                    </span>

                    <div>
                      <strong>Incident requires review</strong>

                      <p>Unusual file activity detected.</p>
                    </div>
                  </div>

                  <div className="notification-entry">
                    <span className="notification-symbol symbol-teal">
                      <Database size={16} />
                    </span>

                    <div>
                      <strong>Backup verified</strong>

                      <p>Latest integrity check completed.</p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="topbar-divider" />

            <span className="environment-status">
              <span />
              Demo environment
            </span>
          </div>
        </header>

        <div className="page-content">
          {currentPage !== "Overview" ? (
            <section className="panel" style={{ padding: 24 }}>
              <div className="panel-header">
                <div>
                  <h2>{pageTitle}</h2>

                  <p>{pageDescription}</p>
                </div>

                <ShieldCheck size={24} />
              </div>

              {currentPage === "Threat detection" && (
                <div>
                  <h3>Detected threats</h3>

                  {events

                    .filter(
                      (event) =>
                        event.color === "red" || event.color === "amber",
                    )

                    .map((event) => (
                      <div key={event.title} className="selected-file">
                        <ShieldAlert size={20} />

                        <div>
                          <strong>{event.title}</strong>

                          <span>
                            {event.severity} · {event.status} · {event.time}
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              )}

              {currentPage === "Incidents" && (
                <div>
                  <h3>Open incidents</h3>

                  <p>Unusual file modification rate — Investigating</p>

                  <p>Suspicious file extension detected — Under review</p>
                </div>
              )}

              {currentPage === "Protected files" && (
                <p>
                  File inventory is currently demo-only. Backend connection is
                  pending.
                </p>
              )}

              {currentPage === "Backup management" && (
                <div>
                  <h3>Backup summary</h3>

                  <p>Successful jobs: 286 (demo)</p>

                  <p>Failed jobs: 04 (demo)</p>

                  <p>Success rate: 98.6% (demo)</p>
                </div>
              )}

              {currentPage === "Recovery center" && (
                <p>Recovery actions are not connected to the backend yet.</p>
              )}

              {currentPage === "Analytics & reports" && (
                <p>
                  Security activity chart is available on the Overview
                  dashboard.
                </p>
              )}

              {currentPage === "Audit logs" && (
                <div>
                  {events.map((event) => (
                    <p key={event.title}>
                      {event.time} — {event.title} — {event.status}
                    </p>
                  ))}
                </div>
              )}

              {currentPage === "Settings" && (
                <p>Workspace settings are currently a frontend preview.</p>
              )}

              <button
                type="button"
                className="button button-secondary"
                onClick={() => selectPage("Overview")}
              >
                <ArrowRight size={15} />
                Back to overview
              </button>
            </section>
          ) : (
            <>
              <div className="page-heading">
                <div>
                  <div className="eyebrow">
                    <span className="eyebrow-line" />
                    SECURITY OPERATIONS
                  </div>

                  <h1>{pageTitle}</h1>

                  <p>{pageDescription}</p>
                </div>

                <div className="heading-actions">
                  <button
                    type="button"
                    className="button button-secondary"
                    onClick={() => fetchDashboardData()}
                    disabled={dashboardLoading}
                  >
                    <RefreshCw size={15} />
                    Refresh
                  </button>

                  <button
                    type="button"
                    className="button button-primary"
                    onClick={() => selectPage("Recovery center")}
                  >
                    <RefreshCw size={15} />
                    Recovery center
                  </button>
                </div>
              </div>

              <div className="demo-notice">
                <span className="demo-notice-icon">
                  <CircleHelp size={16} />
                </span>

                <span>
                  <strong>Live API connected</strong> — Security metrics and
                  recent activity are retrieved from the backend. Backup
                  analytics are unavailable.
                </span>

                <button
                  type="button"
                  aria-label="Dismiss preview notice"
                  onClick={(event) =>
                    event.currentTarget.parentElement.remove()
                  }
                >
                  <X size={16} />
                </button>
              </div>

              <section className="panel upload-panel">
                <div className="panel-header">
                  <div>
                    <h2>Upload a file</h2>

                    <p>
                      Select a file for the security-scanning workflow preview.
                    </p>
                  </div>

                  <UploadCloud size={22} />
                </div>

                <input
                  ref={fileInputRef}
                  id="cloud-shield-file-input"
                  type="file"
                  accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.jpg,.jpeg,.png,.zip"
                  className="upload-input"
                  onChange={(event) => {
                    handleFileSelect(event.target.files?.[0]);

                    event.target.value = "";
                  }}
                />

                {!selectedFile ? (
                  <label
                    htmlFor="cloud-shield-file-input"
                    className={`upload-dropzone ${isDragging ? "upload-dropzone-active" : ""
                      }`}
                    onDragOver={(event) => {
                      event.preventDefault();

                      setIsDragging(true);
                    }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={handleDrop}
                  >
                    <UploadCloud size={30} />

                    <strong>Drag and drop a file here</strong>

                    <span>or click to browse your computer</span>

                    <span className="upload-button-label">Choose file</span>
                  </label>
                ) : (
                  <div className="file-ready-card">
                    <div className="file-ready-heading">
                      <span className="file-ready-icon">
                        <File size={23} />
                      </span>

                      <div className="file-ready-copy">
                        <strong>File ready to scan</strong>

                        <span>
                          Your file is selected and ready for the next step.
                        </span>
                      </div>

                      <span className="file-ready-badge">Selected</span>
                    </div>

                    <div className="selected-file">
                      <File size={20} />

                      <div>
                        <strong>{selectedFile.name}</strong>

                        <span>
                          {selectedFile.size < 1024 * 1024
                            ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                            : `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB`}
                        </span>
                      </div>

                      <button
                        type="button"
                        className="button button-secondary replace-file-button"
                        onClick={() =>
                          document

                            .getElementById("cloud-shield-file-input")

                            ?.click()
                        }
                      >
                        Replace file
                      </button>

                      <button
                        type="button"
                        className="icon-button"
                        aria-label="Remove selected file"
                        onClick={() => {
                          setSelectedFile(null);

                          setUploadMessage("No file selected.");
                        }}
                      >
                        <X size={16} />
                      </button>
                    </div>

                    <div className="upload-submit-row">
                      <button
                        type="button"
                        className="button button-primary upload-submit-button"
                        onClick={handleScan}
                        disabled={!selectedFile || scanStatus === "scanning"}
                      >
                        <UploadCloud size={17} />

                        {scanStatus === "scanning"
                          ? `Scanning... ${scanProgress}%`
                          : scanStatus === "completed"
                            ? "Scan Again"
                            : "Upload & Scan"}
                      </button>
                    </div>

                    {scanStatus === "scanning" && (
                      <div className="scan-progress-card" role="status">
                        <div className="scan-progress-heading">
                          <strong>Scanning file</strong>

                          <span>{scanProgress}%</span>
                        </div>

                        <div
                          className="scan-progress-track"
                          role="progressbar"
                          aria-valuenow={scanProgress}
                          aria-valuemin={0}
                          aria-valuemax={100}
                        >
                          <div
                            className="scan-progress-fill"
                            style={{ width: `${scanProgress}%` }}
                          />
                        </div>

                        <p>Simulating the scanning workflow...</p>
                      </div>
                    )}

                    {scanStatus === "completed" && scanResult && (
                      <div
                        className={`scan-result-card ${scanResult.file?.status === "quarantined"
                            ? "scan-result-infected"
                            : "scan-result-safe"
                          }`}
                        role="status"
                      >
                        <div className="scan-result-heading">
                          <span className="scan-result-icon">
                            {scanResult.file?.status === "quarantined"
                              ? "!"
                              : "✔"}
                          </span>

                          <div>
                            <strong>
                              {scanResult.file?.status === "quarantined"
                                ? "Malware detected!"
                                : "File uploaded successfully"}
                            </strong>
                            <p>{scanResult.message}</p>
                          </div>
                        </div>

                        <div className="scan-result-notice">
                          <span>
                            {scanResult.file?.status === "quarantined"
                              ? "File quarantined"
                              : "Upload verified"}
                          </span>

                          <p>
                            {scanResult.file?.status === "quarantined"
                              ? "ClamAV detected malware. The file has been isolated in quarantine and no trusted backup was created."
                              : "Cloud-Shield scanned the uploaded file and returned its security status."}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div
                  className={`upload-message ${uploadMessage.includes("Invalid") ||
                      uploadMessage.includes("too large") ||
                      uploadMessage.includes("Empty")
                      ? "upload-message-error"
                      : uploadMessage.includes("successfully")
                        ? "upload-message-success"
                        : "upload-message-info"
                    }`}
                  role="status"
                  aria-live="polite"
                >
                  <strong>
                    {uploadMessage.includes("Invalid") ||
                      uploadMessage.includes("too large") ||
                      uploadMessage.includes("Empty")
                      ? "⚠ Validation Error"
                      : uploadMessage.includes("successfully")
                        ? "✓ File Validated"
                        : "ⓘ Upload Status"}
                  </strong>

                  <span>{uploadMessage}</span>
                </div>

                <p className="upload-disclaimer">
                  Files are uploaded to the backend. Malware scanning status is
                  not confirmed by upload success alone.
                </p>
              </section>

              <section className="protection-banner">
                <div className="protection-symbol">
                  <ShieldCheck size={25} />
                </div>

                <div className="protection-copy">
                  <div className="protection-title-row">
                    <h2>Protection overview</h2>

                    <Badge tone="neutral">Monitoring status unavailable</Badge>
                  </div>

                  <p>
                    Your sample workspace is ready for monitoring. Review open
                    incidents and verify your recovery points.
                  </p>
                </div>

                <div className="protection-meta">
                  <span>WORKSPACE STATUS</span>

                  <strong>
                    <span className="status-pulse" />
                    Operational (demo)
                  </strong>
                </div>

                <button
                  type="button"
                  className="banner-arrow"
                  aria-label="View threat detection"
                  onClick={() => selectPage("Threat detection")}
                >
                  <ArrowRight size={19} />
                </button>
              </section>

              <section className="metrics-grid" aria-label="Security metrics">
                {dashboardLoading && (
                  <p role="status">Loading live security metrics...</p>
                )}

                {dashboardError && (
                  <p role="alert">
                    Unable to load security metrics: {dashboardError}
                  </p>
                )}

                {!dashboardLoading && !dashboardError && !dashboardData && (
                  <p role="status">
                    Security metrics are currently unavailable.
                  </p>
                )}
                {dashboardMetrics.map((metric) => (
                  <MetricCard key={metric.label} metric={metric} />
                ))}
              </section>

              <section className="dashboard-grid">
                <article className="panel activity-panel">
                  <div className="panel-header">
                    <div>
                      <h2>Live security activity</h2>
                      <p>Recent activity snapshot</p>
                    </div>
                    <Badge tone="success">
                      {dashboardData?.activity?.riskLevel ?? "Unavailable"}
                    </Badge>
                  </div>

                  <div className="backup-stats">
                    {[
                      {
                        label: "Total activities",
                        value:
                          dashboardData?.detection?.activity?.totalActivities,
                      },
                      {
                        label: "Modifications",
                        value:
                          dashboardData?.detection?.activity?.modifications,
                      },
                      {
                        label: "Renames",
                        value: dashboardData?.detection?.activity?.renames,
                      },
                      {
                        label: "Deletions",
                        value: dashboardData?.detection?.activity?.deletions,
                      },
                      {
                        label: "Extension changes",
                        value:
                          dashboardData?.detection?.activity?.extensionChanges,
                      },
                      {
                        label: "Risk score",
                        value: dashboardData?.activity?.riskScore,
                      },
                    ].map((item) => (
                      <div key={item.label}>
                        <span>{item.label}</span>
                        <strong>{item.value ?? "—"}</strong>
                      </div>
                    ))}
                  </div>

                  <div className="chart-footer">
                    <span>
                      <Activity size={14} />
                      Live data · Last 30 seconds
                    </span>
                    <button
                      type="button"
                      onClick={() => selectPage("Analytics & reports")}
                    >
                      View analytics <ArrowRight size={14} />
                    </button>
                  </div>
                </article>

                <article className="panel backup-panel">
                  <div className="panel-header">
                    <div>
                      <h2>Backup health</h2>
                      <p>Recovery readiness</p>
                    </div>

                    <button
                      type="button"
                      className="icon-button subtle-icon"
                      aria-label="Backup options"
                      onClick={() =>
                        notify("Backup health data is not available yet.")
                      }
                    >
                      <MoreHorizontal size={19} />
                    </button>
                  </div>

                  <div className="backup-score">
                    <div className="backup-score-copy">
                      <Badge tone="neutral">Unavailable</Badge>
                      <p>metrics are not currently provided by the backend.</p>
                    </div>
                  </div>

                  <button
                    type="button"
                    className="text-link backup-link"
                    onClick={() => selectPage("Backup management")}
                  >
                    View backup management <ArrowRight size={14} />
                  </button>
                </article>
              </section>

              <section className="panel events-panel">
                <div className="panel-header events-heading">
                  <div>
                    <h2>Recent security events</h2>

                    <p>Latest security events from backend</p>
                  </div>

                  <button
                    type="button"
                    className="button button-secondary button-small"
                    onClick={() => selectPage("Threat detection")}
                  >
                    View all events <ArrowRight size={14} />
                  </button>
                </div>

                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>EVENT</th>

                        <th>AFFECTED ASSET</th>

                        <th>TIME</th>

                        <th>SEVERITY</th>

                        <th>STATUS</th>

                        <th aria-label="Actions" />
                      </tr>
                    </thead>

                    <tbody>
                      {filteredEvents.map((event) => (
                        <tr key={`${event.title}-${event.time}`}>
                          <td>
                            <div className="event-title-cell">
                              <span
                                className={`event-icon event-icon-${event.color}`}
                              >
                                {event.color === "red" ? (
                                  <ShieldAlert size={16} />
                                ) : event.color === "amber" ? (
                                  <FileSearch size={16} />
                                ) : (
                                  <ShieldCheck size={16} />
                                )}
                              </span>

                              <span>{event.title}</span>
                            </div>
                          </td>

                          <td>
                            <code>{event.asset}</code>
                          </td>

                          <td className="event-time">{event.time}</td>

                          <td>
                            <Badge
                              tone={
                                event.color === "red"
                                  ? "danger"
                                  : event.color === "amber"
                                    ? "warning"
                                    : "info"
                              }
                            >
                              {event.severity}
                            </Badge>
                          </td>

                          <td>
                            <span
                              className={`status-text status-${event.color}`}
                            >
                              <span />

                              {event.status}
                            </span>
                          </td>

                          <td>
                            <button
                              type="button"
                              className="row-action"
                              aria-label={`View ${event.title}`}
                              onClick={() =>
                                notify(`Demo event: ${event.title}`)
                              }
                            >
                              <ArrowUpRight size={16} />
                            </button>
                          </td>
                        </tr>
                      ))}

                      {filteredEvents.length === 0 && (
                        <tr>
                          <td colSpan="6" className="empty-state">
                            {search
                              ? `No security events match "${search}".`
                              : "No security events recorded yet."}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                <div className="table-footer">
                  <span>
                    Showing {filteredEvents.length} of {events.length} security
                    events
                  </span>

                  <button type="button" onClick={() => setSearch("")}>
                    Clear search <X size={13} />
                  </button>
                </div>
              </section>

              <footer className="page-footer">
                <span>
                  Cloud-Shield <span className="footer-separator">·</span>{" "}
                  Security &amp; recovery workspace
                </span>

                <span>
                  <span className="footer-status-dot" /> API connected{" "}
                  <span className="footer-separator">·</span> Live security
                  activity available
                </span>
              </footer>
            </>
          )}
        </div>
      </main>

      {showEditProfile && (
        <div className="profile-modal-backdrop">
          <section
            className="profile-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="profile-modal-title"
          >
            <div className="profile-modal-header">
              <div>
                <span>ACCOUNT SETTINGS</span>
                <h2 id="profile-modal-title">Edit Profile</h2>
                <p>Update your personal information.</p>
              </div>

              <button
                type="button"
                className="profile-modal-close"
                aria-label="Close modal"
                onClick={() => setShowEditProfile(false)}
              >
                <X size={19} />
              </button>
            </div>

            <form onSubmit={handleUpdateProfile}>
              <label className="profile-form-field">
                Full Name
                <input
                  type="text"
                  value={editFullName}
                  onChange={(event) => setEditFullName(event.target.value)}
                  placeholder="Enter your full name"
                  maxLength={80}
                  required
                />
              </label>

              <label className="profile-form-field">
                Email Address
                <input type="email" value={user?.email || ""} disabled />
              </label>

              <label className="profile-form-field">
                Account Role
                <input type="text" value={user?.role || "User"} disabled />
              </label>

              {profileError && (
                <p className="profile-form-error" role="alert">
                  {profileError}
                </p>
              )}

              <div className="profile-modal-actions">
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={() => setShowEditProfile(false)}
                  disabled={profileSaving}
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  className="button button-primary"
                  disabled={profileSaving}
                >
                  {profileSaving ? "Saving..." : "Save Changes"}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}

      {toast && (
        <div className="toast-message">
          <Check size={17} />

          {toast}

          <button
            type="button"
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
