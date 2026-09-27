package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestYeguoProbeLive 直接调用真实的野果发现流程并逐步打印耗时，
// 用于在真实网络环境下定位「野果线路暂不可用」卡在哪一步。
//
//	YEGUO_PROBE=1 go test -run TestYeguoProbeLive -v ./core/
func TestYeguoProbeLive(t *testing.T) {
	if os.Getenv("YEGUO_PROBE") == "" {
		t.Skip("设置 YEGUO_PROBE=1 才运行")
	}

	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.dataDir = dir
	cfg.Retries = 1

	router := &proxyRouter{}
	d := &Downloader{
		cfg:           cfg,
		providerHosts: map[string]string{},
		proxyRouter:   router,
		limiter:       newRequestLimiter(3, 250*time.Millisecond),
		diagnostics:   newDiagnosticLog(dir),
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxIdleConnsPerHost = 8
	transport.ResponseHeaderTimeout = 20 * time.Second
	transport.Proxy = router.proxy
	cdn := newCDNTransport(transport, newDNSResolver(transport))
	d.client = &http.Client{Transport: newHuangguoBrowserTransport(cdn, d), Timeout: 45 * time.Second}

	client := d.yeguoClient()
	log := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	log("############ 配置自检 ############")
	log("  入口 site       = %s", client.site)
	log("  线路发现页       = %s", yeguoTransitURL)
	log("  tcpOnly 判定：")
	for _, h := range []string{"ygdj7.com", "analyze.buxefaex.cc", "analyze.fzchosdi.cc", "www.yeguodj.com"} {
		want := "TCP"
		if h == "www.yeguodj.com" {
			want = "HTTP/3(必须)"
		}
		got := "HTTP/3"
		if tcpOnlyHost(h) {
			got = "TCP"
		}
		mark := "✅"
		if (want == "TCP") != (got == "TCP") {
			mark = "❌"
		}
		log("    %-26s → %-12s %s", h, got, mark)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	log("")
	log("############ [1] 抓线路发现页 ygdj7.com ############")
	t0 := time.Now()
	sites := client.discoverTransitSites(ctx)
	log("  耗时 %.2fs，发现 %d 个线路", time.Since(t0).Seconds(), len(sites))
	for _, s := range sites {
		log("    - %s", s)
	}

	log("")
	log("############ [2] 完整 discoverConfiguration ############")
	t2 := time.Now()
	access, err := client.discoverConfiguration(ctx)
	if err != nil {
		log("  [FAIL %.2fs] %v", time.Since(t2).Seconds(), err)
	} else {
		log("  [OK   %.2fs] site=%s", time.Since(t2).Seconds(), access.site)
		log("               apiBase=%s", access.base)
	}

	log("")
	log("############ [3] 端到端：实际调用接口（走 yeguodj.com，必须 HTTP/3）############")
	for _, route := range []string{"/api/home/contentOptions", "/api/theater/exploreList", "/api/search/result"} {
		t3 := time.Now()
		params := url.Values{"page": {"1"}}
		if route == "/api/search/result" {
			params = url.Values{"keyword": {"短剧"}, "page": {"1"}}
		}
		result, err := client.call(ctx, route, params)
		if err != nil {
			log("  [FAIL %6.2fs] %-28s %v", time.Since(t3).Seconds(), route, trimProbe(err.Error(), 70))
			continue
		}
		keys := ""
		for k := range result {
			keys += k + " "
		}
		log("  [OK   %6.2fs] %-28s 返回字段: %s", time.Since(t3).Seconds(), route, trimProbe(keys, 60))
	}

	log("")
	log("############ [4] 单独计时：4 条 fzchosdi 死线路（DNS 污染，仅作参考）############")
	for _, site := range sites {
		t4 := time.Now()
		_, err := client.discoverConfigurationAt(ctx, site)
		if err != nil {
			log("  [FAIL %6.2fs] %-34s %v", time.Since(t4).Seconds(), site, trimProbe(err.Error(), 60))
		} else {
			log("  [OK   %6.2fs] %-34s", time.Since(t4).Seconds(), site)
		}
	}
}

func trimProbe(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
