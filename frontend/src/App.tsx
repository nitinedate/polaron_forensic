import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./lib/auth";
import { lazy, Suspense, type ReactNode } from "react";
import { AppLayout } from "./components/AppLayout";
import { LogsPage } from "./pages/LogsPage";
import { Login } from "./pages/Login";
import { ForgotPassword } from "./pages/ForgotPassword";
import { ResetPassword } from "./pages/ResetPassword";
import { ActivateAccount } from "./pages/ActivateAccount";
import { Dashboard } from "./pages/Dashboard";
import { JobsListPage } from "./pages/forensic/JobsListPage";
import { JobNewPage } from "./pages/forensic/JobNewPage";
import { JobDetailPage } from "./pages/forensic/JobDetailPage";
import { MobileExtractionListPage } from "./pages/forensic/MobileExtractionListPage";
import { MobileExtractionNewPage } from "./pages/forensic/MobileExtractionNewPage";
import { MobileAcquisitionPage } from "./pages/forensic/MobileAcquisitionPage";
import { MobileJobsPage } from "./pages/mobile/MobileJobsPage";
import { MobileNewJobPage } from "./pages/mobile/MobileNewJobPage";
import { MobileCompactJobPage } from "./pages/mobile/MobileCompactJobPage";
const MobileReportPage = lazy(() => import("./pages/mobile/MobileReportPage").then(module => ({ default: module.MobileReportPage })));
import {
  MobileAcquisitionHubPage,
  MobileImageProcessingPage,
  MobileOverviewPage,
  MobileRagDirectoryPage,
  MobileReportsDirectoryPage,
  MobileUnifiedJobsPage,
} from "./pages/mobile/MobileConsolePages";
import { JobIntakePage } from "./pages/forensic/JobIntakePage";
const ReportEditorPage = lazy(() => import("./pages/forensic/ReportEditorPage").then(module => ({ default: module.ReportEditorPage })));
const ReportListPage = lazy(() => import("./pages/forensic/ReportListPage").then(module => ({ default: module.ReportListPage })));
import { SearchEvidencePage } from "./pages/forensic/SearchEvidencePage";
import { ArtifactExplorerPage } from "./pages/forensic/ArtifactExplorerPage";
import { DiskArtifactsHubPage } from "./pages/forensic/DiskArtifactsHubPage";
import { MobileArtifactsDirectoryPage } from "./pages/mobile/MobileArtifactsDirectoryPage";
import { MobileArtifactsPage } from "./pages/mobile/MobileArtifactsPage";
import { ArtifactSelectionPage } from "./pages/forensic/ArtifactSelectionPage";
import { CaseOverviewPage } from "./pages/forensic/CaseOverviewPage";
import { ArtifactCaptureLogPage } from "./pages/forensic/ArtifactCaptureLogPage";
import { ImageEvidencePage } from "./pages/forensic/ImageEvidencePage";
import { Users } from "./pages/Users";
import { Roles } from "./pages/Roles";
import { Permissions } from "./pages/Permissions";
import { Tenants } from "./pages/Tenants";
import { FirmIam } from "./pages/FirmIam";
import { Security } from "./pages/Security";
import { Profile } from "./pages/Profile";
import { AppearancePage } from "./pages/settings/AppearancePage";
import { VulnDashboardsPage } from "./pages/vuln/dashboards/VulnDashboardsPage";
import { VulnOpsHomePage } from "./pages/vuln/VulnOpsHomePage";
import { RiskDashboardPage } from "./pages/vuln/RiskDashboardPage";
import { ScannersPage } from "./pages/vuln/ScannersPage";
import { ConnectNetworkPage } from "./pages/vuln/ConnectNetworkPage";
import { ScanPoliciesPage } from "./pages/vuln/ScanPoliciesPage";
import { ScanJobsPage } from "./pages/vuln/ScanJobsPage";
import { VulnExplorerPage } from "./pages/vuln/VulnExplorerPage";
import { RemediationBoardPage } from "./pages/vuln/RemediationBoardPage";
import { TimelinePage } from "./pages/vuln/TimelinePage";
import { ReportsExportPage } from "./pages/vuln/ReportsExportPage";
import { ExceptionsPage } from "./pages/vuln/ExceptionsPage";
import { Asset360Page } from "./pages/vuln/Asset360Page";
import { AgentsPage } from "./pages/vuln/AgentsPage";
import { CredentialsPage } from "./pages/vuln/CredentialsPage";
import { isVulnModuleEnabled } from "./lib/vulnFlags";
import { isDedicatedMobileService, isForensicService, isLegacyMobileExtractService, isUnifiedService } from "./lib/serviceMode";

function FullScreenLoader() {
  return (
    <div className="flex h-screen items-center justify-center bg-ink-50">
      <div className="h-10 w-10 animate-spin rounded-full border-4 border-ink-200 border-t-brand-500" />
    </div>
  );
}

function Protected({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <FullScreenLoader />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function PublicOnly({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const activated = new URLSearchParams(window.location.search).get("activated") === "1";
  if (loading) return <FullScreenLoader />;
  if (user && !activated) return <Navigate to="/" replace />;
  return <>{children}</>;
}

function RequirePermission({ perm, children }: { perm: string; children: ReactNode }) {
  const { hasPermission } = useAuth();
  if (!hasPermission(perm)) return <Navigate to="/profile" replace />;
  return <>{children}</>;
}

function RequireFirmScope({ children }: { children: ReactNode }) {
  const { isPlatformScope } = useAuth();
  if (isPlatformScope) return <Navigate to="/" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Suspense fallback={<div className="p-6 text-sm" role="status">Loading report…</div>}><Routes>
      <Route path="/login" element={<PublicOnly><Login /></PublicOnly>} />
      <Route path="/forgot-password" element={<PublicOnly><ForgotPassword /></PublicOnly>} />
      <Route path="/activate" element={<ActivateAccount />} />
      <Route path="/reset-password" element={<ResetPassword />} />

      <Route
        path="/"
        element={
          <Protected>
            <AppLayout />
          </Protected>
        }
      >
        <Route index element={<Dashboard />} />
        <Route
          path="logs"
          element={
            <RequireFirmScope>
              <LogsPage />
            </RequireFirmScope>
          }
        />
        <Route
          path="users"
          element={
            <RequireFirmScope>
              <RequirePermission perm="user:read">
                <Users />
              </RequirePermission>
            </RequireFirmScope>
          }
        />
        <Route
          path="roles"
          element={
            <RequireFirmScope>
              <RequirePermission perm="role:read">
                <Roles />
              </RequirePermission>
            </RequireFirmScope>
          }
        />
        <Route
          path="permissions"
          element={
            <RequireFirmScope>
              <RequirePermission perm="permission:read">
                <Permissions />
              </RequirePermission>
            </RequireFirmScope>
          }
        />
        <Route
          path="tenants"
          element={
            <RequirePermission perm="tenant:manage">
              <Tenants />
            </RequirePermission>
          }
        />
        <Route
          path="tenants/:firmId/iam"
          element={
            <RequirePermission perm="tenant:manage">
              <FirmIam />
            </RequirePermission>
          }
        />
        <Route path="profile" element={<Profile />} />
        <Route path="security" element={<Security />} />
        <Route path="settings/appearance" element={<AppearancePage />} />
        {isUnifiedService() && (
          <Route path="mobile" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileOverviewPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isUnifiedService() && (
          <Route path="mobile/acquisition" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileAcquisitionHubPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isUnifiedService() && (
          <Route path="mobile/images" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileImageProcessingPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isUnifiedService() && (
          <Route path="mobile/jobs" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileUnifiedJobsPage /></RequirePermission></RequireFirmScope>} />
        )}
        {(isUnifiedService() || isDedicatedMobileService()) && (
          <Route path="mobile/artifacts" element={<RequireFirmScope><RequirePermission perm="artifact:read"><MobileArtifactsDirectoryPage /></RequirePermission></RequireFirmScope>} />
        )}
        {(isUnifiedService() || isDedicatedMobileService()) && (
          <Route path="mobile/rag" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileRagDirectoryPage /></RequirePermission></RequireFirmScope>} />
        )}
        {(isUnifiedService() || isDedicatedMobileService()) && (
          <Route path="mobile/reports" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileReportsDirectoryPage /></RequirePermission></RequireFirmScope>} />
        )}

        {isDedicatedMobileService() && (
          <Route path="mobile" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileJobsPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isDedicatedMobileService() && (
          <Route path="mobile/new" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileNewJobPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isDedicatedMobileService() && (
          <Route path="mobile/acquire" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileAcquisitionPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isDedicatedMobileService() && (
          <Route path="mobile/jobs/:jobId" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileCompactJobPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isDedicatedMobileService() && (
          <Route path="mobile/jobs/:jobId/artifacts" element={<RequireFirmScope><RequirePermission perm="artifact:read"><MobileArtifactsPage /></RequirePermission></RequireFirmScope>} />
        )}
        {isDedicatedMobileService() && (
          <Route path="mobile/jobs/:jobId/intake" element={<RequireFirmScope><RequirePermission perm="job:run"><JobIntakePage /></RequirePermission></RequireFirmScope>} />
        )}
        {isDedicatedMobileService() && (
          <Route path="mobile/jobs/:jobId/report" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileReportPage /></RequirePermission></RequireFirmScope>} />
        )}

        {isUnifiedService() && (
          <>
            <Route path="mobile/android" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileJobsPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/android/new" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileNewJobPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/android/acquire" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileAcquisitionPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/android/jobs/:jobId" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileCompactJobPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/android/jobs/:jobId/artifacts" element={<RequireFirmScope><RequirePermission perm="artifact:read"><MobileArtifactsPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/android/jobs/:jobId/intake" element={<RequireFirmScope><RequirePermission perm="job:run"><JobIntakePage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/android/jobs/:jobId/report" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileReportPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/ios" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileJobsPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/ios/new" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileNewJobPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/ios/acquire" element={<RequireFirmScope><RequirePermission perm="job:run"><MobileAcquisitionPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/ios/jobs/:jobId" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileCompactJobPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/ios/jobs/:jobId/artifacts" element={<RequireFirmScope><RequirePermission perm="artifact:read"><MobileArtifactsPage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/ios/jobs/:jobId/intake" element={<RequireFirmScope><RequirePermission perm="job:run"><JobIntakePage /></RequirePermission></RequireFirmScope>} />
            <Route path="mobile/ios/jobs/:jobId/report" element={<RequireFirmScope><RequirePermission perm="job:read"><MobileReportPage /></RequirePermission></RequireFirmScope>} />
          </>
        )}
        {isForensicService() && (
          <Route
            path="forensic/image-evidence"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:run">
                  <ImageEvidencePage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/artifacts"
            element={
              <RequireFirmScope>
                <RequirePermission perm="artifact:read">
                  <DiskArtifactsHubPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/jobs"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <JobsListPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isLegacyMobileExtractService() && (
          <Route
            path="forensic/mobile"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <MobileExtractionListPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isLegacyMobileExtractService() && (
          <Route
            path="forensic/mobile/new"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:run">
                  <MobileExtractionNewPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isLegacyMobileExtractService() && (
          <Route
            path="forensic/mobile/acquire"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:run">
                  <MobileAcquisitionPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/jobs/new"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:run">
                  <JobNewPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {(isForensicService() || isLegacyMobileExtractService()) && (
          <Route
            path="forensic/jobs/:jobId"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <JobDetailPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/jobs/:jobId/intake"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:run">
                  <JobIntakePage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/reports"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <ReportListPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/evidence-search"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <SearchEvidencePage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/jobs/:jobId/report"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <ReportEditorPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {(isForensicService() || isLegacyMobileExtractService()) && (
          <Route
            path="forensic/jobs/:jobId/artifacts"
            element={
              <RequireFirmScope>
                <RequirePermission perm="artifact:read">
                  <ArtifactExplorerPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/jobs/:jobId/artifact-scope"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:run">
                  <ArtifactSelectionPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {isForensicService() && (
          <Route
            path="forensic/jobs/:jobId/select-artifacts"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:run">
                  <ArtifactSelectionPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {(isForensicService() || isLegacyMobileExtractService()) && (
          <Route
            path="forensic/jobs/:jobId/capture-log"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <ArtifactCaptureLogPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}
        {(isForensicService() || isLegacyMobileExtractService()) && (
          <Route
            path="forensic/cases/:caseId"
            element={
              <RequireFirmScope>
                <RequirePermission perm="job:read">
                  <CaseOverviewPage />
                </RequirePermission>
              </RequireFirmScope>
            }
          />
        )}

        {/* Vulnerability / Nessus module — additive routes; gated by feature flag */}
        {isVulnModuleEnabled() && (
          <>
            <Route
              path="vuln/dashboards"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="vuln:read">
                    <VulnDashboardsPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/risk"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="vuln:read">
                    <RiskDashboardPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/ops"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="scan:read">
                    <VulnOpsHomePage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/scanners"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="scan:read">
                    <ScannersPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/connect"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="scan:read">
                    <ConnectNetworkPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/policies"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="scan:read">
                    <ScanPoliciesPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/scans"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="scan:read">
                    <ScanJobsPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/findings"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="vuln:read">
                    <VulnExplorerPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/remediation"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="vuln:read">
                    <RemediationBoardPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/exceptions"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="vuln:read">
                    <ExceptionsPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/timeline"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="vuln:read">
                    <TimelinePage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/reports"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="vuln:read">
                    <ReportsExportPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/assets/:assetId"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="asset:read">
                    <Asset360Page />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/agents"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="agent:read">
                    <AgentsPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
            <Route
              path="vuln/credentials"
              element={
                <RequireFirmScope>
                  <RequirePermission perm="credential:read">
                    <CredentialsPage />
                  </RequirePermission>
                </RequireFirmScope>
              }
            />
          </>
        )}
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes></Suspense>
  );
}
