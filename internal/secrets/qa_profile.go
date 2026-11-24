package secrets

import (
	"encoding/json"
	"os"
	"sort"
)

type Persona struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	About    string `json:"about"`
}
type QASecret struct {
	Value string `json:"value"`
	About string `json:"about"`
}
type QAProfile struct {
	Vercel   map[string]string   `json:"vercel"`
	Personas map[string]Persona  `json:"personas"`
	Secrets  map[string]QASecret `json:"secrets"`
	Source   string              `json:"-"`
}

func LoadQAProfile(path string, legacy map[string]string) (*QAProfile, error) {
	p := &QAProfile{Vercel: map[string]string{}, Personas: map[string]Persona{}, Secrets: map[string]QASecret{}}
	b, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(b, p); e != nil {
			return nil, e
		}
		p.Source = path
		return p, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	for _, k := range []string{"TOKEN", "TEAM_ID", "WEB_PROJECT_ID", "API_PROJECT_ID", "WEB_BYPASS_SECRET", "API_BYPASS_SECRET"} {
		if v := legacy["VERCEL_"+k]; v != "" {
			p.Vercel[lower(k)] = v
		}
	}
	email, password := legacy["PREVIEW_TEST_EMAIL"], legacy["PREVIEW_TEST_PASSWORD"]
	if email != "" && password != "" {
		p.Personas["primary"] = Persona{Email: email, Password: password, About: "The preview test account"}
	}
	p.Source = "legacy"
	return p, nil
}
func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
func (p *QAProfile) KnownValues() []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, k := range []string{"token", "web_bypass_secret", "api_bypass_secret"} {
		if p.Vercel[k] != "" {
			out = append(out, p.Vercel[k])
		}
	}
	for _, v := range p.Personas {
		out = append(out, v.Email, v.Password)
	}
	for _, v := range p.Secrets {
		out = append(out, v.Value)
	}
	filtered := out[:0]
	for _, v := range out {
		if v != "" {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
func (p *QAProfile) Describe() map[string]any {
	out := map[string]any{"source": p.Source, "vercel": []string{}, "personas": map[string]string{}, "secrets": map[string]string{}}
	if p == nil {
		return out
	}
	v := out["vercel"].([]string)
	for k, x := range p.Vercel {
		if x != "" {
			v = append(v, k)
		}
	}
	sort.Strings(v)
	out["vercel"] = v
	ps := out["personas"].(map[string]string)
	for k, x := range p.Personas {
		ps[k] = x.About
	}
	ss := out["secrets"].(map[string]string)
	for k, x := range p.Secrets {
		ss[k] = x.About
	}
	return out
}
