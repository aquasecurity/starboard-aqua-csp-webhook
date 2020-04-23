package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/ext"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/starboard"
	sec "github.com/aquasecurity/starboard-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var NoError error = nil

type mockWriter struct {
	mock.Mock
}

func (m *mockWriter) Write(name string, report sec.VulnerabilityReport) (err error) {
	args := m.Called(name, report)
	return args.Error(0)
}

func TestHandler_AcceptScanReport(t *testing.T) {

	t.Run("GET / should return method not allowed status code", func(t *testing.T) {
		converter := starboard.NewConverter(ext.SystemClock)
		writer := &mockWriter{}
		handler := NewHandler(converter, writer)
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := server.Client().Get(server.URL + "/")
		require.NoError(t, err)
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		writer.AssertExpectations(t)
	})

	t.Run("POST / should return bad request status code when post body is not a valid JSON", func(t *testing.T) {
		converter := starboard.NewConverter(ext.SystemClock)
		writer := &mockWriter{}
		handler := NewHandler(converter, writer)
		server := httptest.NewServer(handler)
		defer server.Close()

		resp, err := server.Client().Post(server.URL+"/", "application/json", strings.NewReader("XYZ"))
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		writer.AssertExpectations(t)
	})

	t.Run("POST / should return accepted status code when scan report is transformed and saved as CR instance", func(t *testing.T) {
		now := time.Now()
		converter := starboard.NewConverter(ext.NewFixedClock(now))
		writer := &mockWriter{}
		writer.On("Write", "sha256.9bf8e3dfef5c248bc8880d228241887a1f411b0d2700150e3eeb6ad8c5763df2", sec.VulnerabilityReport{
			GeneratedAt: metav1.NewTime(now),
			Scanner: sec.Scanner{
				Name:   "Aqua CSP",
				Vendor: "Aqua Security",
			},
			Summary: sec.VulnerabilitySummary{
				CriticalCount: 1,
				HighCount:     2,
				MediumCount:   0,
				LowCount:      0,
				UnknownCount:  0,
			},
			Vulnerabilities: []sec.VulnerabilityItem{
				{
					VulnerabilityID:  "CVE-2017-5932",
					Resource:         "bash",
					InstalledVersion: "4.4",
					Severity:         sec.SeverityHigh,
					Description:      "The path autocompletion feature in Bash 4.4 allows local users to gain privileges via a crafted filename starting with a \" (double quote) character and a command substitution metacharacter.",
					Links: []string{
						"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5932",
					},
				},
				{
					VulnerabilityID:  "CVE-2019-18276",
					Resource:         "bash",
					InstalledVersion: "4.4",
					FixedVersion:     "",
					Severity:         sec.SeverityHigh,
					Description:      "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
					Links: []string{
						"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-18276",
					},
				},
				{
					VulnerabilityID:  "CVE-2019-9169",
					Resource:         "glibc",
					InstalledVersion: "2.28",
					FixedVersion:     "",
					Severity:         sec.SeverityCritical,
					Description:      "In the GNU C Library (aka glibc or libc6) through 2.29, proceed_next_node in posix/regexec.c has a heap-based buffer over-read via an attempted case-insensitive regular-expression match.",
					Links: []string{
						"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-9169",
					},
				},
			},
		}).Return(NoError)

		handler := NewHandler(converter, writer)
		server := httptest.NewServer(handler)
		defer server.Close()

		scanReportJSON, err := os.Open("fixture/aqua_scan_report_photon_20200202.json")
		require.NoError(t, err)
		defer func() {
			_ = scanReportJSON.Close()
		}()

		resp, err := server.Client().Post(server.URL+"/", "application/json", scanReportJSON)
		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, resp.StatusCode)
		writer.AssertExpectations(t)
	})

}
