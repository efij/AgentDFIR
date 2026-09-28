package netdest

import "strings"

// Trusted services that carry exfiltration and command-and-control because
// nobody blocks them. Every entry is a service a real incident used or a
// class of service it stood for:
//
//	shortener        the OpenAI–Hugging Face agents chained ~900,000 link-shortener URLs into programs
//	screenshot       …and read responses back through a screenshot service (mShots)
//	request-bin      Shai-Hulud 1 posted secrets to webhook.site
//	serverless-edge  SANDWORM_MODE exfiltrated to a *.workers.dev endpoint
//	blockchain-rpc   the keyv wave (Aug 2026) read its C2 address from an Ethereum contract
//	tunnel           reverse tunnels expose a local listener to the internet
//	paste            paste and file-drop sites
//	chat-webhook     Discord / Telegram / Slack webhooks
//
// Categories marked coveredByPack are already alerted on by the community
// pack's WEBHOOK_C2_EXFIL / PASTE_SITE_DESTINATION rules; Category still
// names them (timeline, exports) but EGRESS_VIA_TRUSTED_SERVICE does not
// raise a second finding for the same command.
var categories = []struct {
	name          string
	coveredByPack bool
	suffixes      []string
}{
	{"shortener", false, []string{"bit.ly", "tinyurl.com", "is.gd", "v.gd", "t.co", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "ow.ly", "buff.ly", "rb.gy", "t.ly", "s.id", "shorturl.gg", "clck.ru", "urlz.fr", "surl.li", "goo.su"}},
	{"screenshot", false, []string{"s.wordpress.com", "s0.wp.com", "urlbox.io", "api.screenshotone.com", "screenshotapi.net", "htmlcsstoimg.com", "hcti.io", "image.thum.io", "api.apiflash.com", "shot.screenshotapi.net", "render-tron.appspot.com"}},
	{"request-bin", true, []string{"webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "beeceptor.com", "hookbin.com", "requestcatcher.com", "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "oastify.com", "burpcollaborator.net", "dnslog.cn", "canarytokens.com", "httpbin.org", "httpbun.com", "postb.in", "ptsv3.com"}},
	{"serverless-edge", false, []string{"workers.dev", "pages.dev", "vercel.app", "netlify.app", "deno.dev", "script.google.com", "script.googleusercontent.com", "glitch.me", "repl.co", "onrender.com", "fly.dev", "herokuapp.com"}},
	{"blockchain-rpc", false, []string{"infura.io", "alchemy.com", "alchemyapi.io", "nodereal.io", "getblock.io", "llamarpc.com", "cloudflare-eth.com", "ankr.com", "quicknode.pro", "publicnode.com", "api.trongrid.io", "mainnet.helius-rpc.com", "api.mainnet-beta.solana.com"}},
	{"tunnel", false, []string{"trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok-free.dev", "loca.lt", "serveo.net", "localhost.run", "lhr.life", "pinggy.link", "bore.pub", "localtonet.com", "tunnelmole.net"}},
	{"paste", true, []string{"pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co", "rentry.org", "dpaste.org", "dpaste.com", "termbin.com", "transfer.sh", "0x0.st", "file.io", "gofile.io", "catbox.moe", "litterbox.catbox.moe", "tmpfiles.org", "bashupload.com", "temp.sh", "oshi.at", "pixeldrain.com"}},
	{"chat-webhook", true, []string{"discord.com", "discordapp.com", "api.telegram.org", "hooks.slack.com"}},
}

// Category names the trusted-service class a destination belongs to, or ""
// when it is none of them.
func Category(dest string) string {
	c, _ := category(dest)
	return c
}

// CoveredByPack reports whether the category is alerted on by an existing
// community-pack rule.
func CoveredByPack(cat string) bool {
	for _, c := range categories {
		if c.name == cat {
			return c.coveredByPack
		}
	}
	return false
}

func category(dest string) (string, bool) {
	h := strings.TrimSuffix(strings.ToLower(Host(dest)), ".")
	for _, c := range categories {
		for _, s := range c.suffixes {
			if h == s || strings.HasSuffix(h, "."+s) {
				return c.name, c.coveredByPack
			}
		}
	}
	return "", false
}
