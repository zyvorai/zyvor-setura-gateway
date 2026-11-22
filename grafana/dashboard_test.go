package grafana_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/zyvorai/zyvor-setura-gateway/grafana"
	"github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

type panel struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Datasource  struct {
		Type string `json:"type"`
		UID  string `json:"uid"`
	} `json:"datasource"`
	GridPos struct{ X, Y, W, H int } `json:"gridPos"`
	Targets []struct {
		Expr       string `json:"expr"`
		Datasource struct {
			UID string `json:"uid"`
		} `json:"datasource"`
	} `json:"targets"`
	FieldConfig struct {
		Defaults struct {
			Unit string `json:"unit"`
		} `json:"defaults"`
	} `json:"fieldConfig"`
	Panels []panel `json:"panels"`
}

type dashboard struct {
	UID           string `json:"uid"`
	Title         string `json:"title"`
	SchemaVersion int    `json:"schemaVersion"`
	Panels        []panel
	Templating    struct {
		List []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Query any    `json:"query"`
		} `json:"list"`
	} `json:"templating"`
}

func load(t *testing.T) (dashboard, []panel) {
	t.Helper()
	b, err := os.ReadFile("setura-gateway.json")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatal("setura-gateway.json is not valid JSON")
	}
	if string(b) != string(grafana.Dashboard) {
		t.Error("the embedded dashboard differs from the file")
	}
	var d dashboard
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	var flat func(ps []panel) []panel
	flat = func(ps []panel) []panel {
		var out []panel
		for _, p := range ps {
			out = append(out, p)
			out = append(out, flat(p.Panels)...)
		}
		return out
	}
	return d, flat(d.Panels)
}

func TestDashboardStructure(t *testing.T) {
	d, ps := load(t)
	if d.UID == "" || d.Title == "" || d.SchemaVersion < 36 {
		t.Errorf("uid %q title %q schema %d", d.UID, d.Title, d.SchemaVersion)
	}
	if len(ps) == 0 || len(ps) > 14 {
		t.Errorf("%d panels: a calm dashboard has a dozen at most", len(ps))
	}
	ids := map[int]bool{}
	for _, p := range ps {
		if p.ID <= 0 || ids[p.ID] {
			t.Errorf("panel id %d (%s) is missing or duplicated", p.ID, p.Title)
		}
		ids[p.ID] = true
		if strings.TrimSpace(p.Title) == "" || strings.TrimSpace(p.Description) == "" {
			t.Errorf("panel %d needs a title and a description", p.ID)
		}
		if p.GridPos.W <= 0 || p.GridPos.H <= 0 || p.GridPos.X < 0 || p.GridPos.X+p.GridPos.W > 24 {
			t.Errorf("panel %q gridPos %+v", p.Title, p.GridPos)
		}
		if p.Datasource.UID != "${datasource}" {
			t.Errorf("panel %q must use the ${datasource} variable, not %q", p.Title, p.Datasource.UID)
		}
		for _, tg := range p.Targets {
			if tg.Datasource.UID != "${datasource}" || tg.Expr == "" {
				t.Errorf("panel %q has a target without the data source variable or expression", p.Title)
			}
		}
		if p.Type != "state-timeline" && p.FieldConfig.Defaults.Unit == "" {
			t.Errorf("panel %q has no unit", p.Title)
		}
	}
	// panels do not overlap
	for i, a := range ps {
		for _, b := range ps[i+1:] {
			if a.GridPos.X < b.GridPos.X+b.GridPos.W && b.GridPos.X < a.GridPos.X+a.GridPos.W &&
				a.GridPos.Y < b.GridPos.Y+b.GridPos.H && b.GridPos.Y < a.GridPos.Y+a.GridPos.H {
				t.Errorf("panels %q and %q overlap", a.Title, b.Title)
			}
		}
	}
}

func TestDashboardDatasourceVariables(t *testing.T) {
	d, ps := load(t)
	vars := map[string]string{}
	for _, v := range d.Templating.List {
		vars[v.Name] = v.Type
	}
	if vars["datasource"] != "datasource" {
		t.Errorf("the datasource variable must be of type datasource: %v", vars)
	}
	if vars["route"] != "query" {
		t.Errorf("route variable: %v", vars)
	}
	used := false
	for _, p := range ps {
		for _, tg := range p.Targets {
			used = used || strings.Contains(tg.Expr, "$route")
			for _, ref := range regexp.MustCompile(`\$(\w+)`).FindAllStringSubmatch(tg.Expr, -1) {
				if _, ok := vars[ref[1]]; !ok && !strings.HasPrefix(ref[1], "__") {
					t.Errorf("panel %q uses undefined variable $%s", p.Title, ref[1])
				}
			}
		}
	}
	if !used {
		t.Error("no panel filters on $route")
	}
}

func TestDashboardOnlyQueriesExposedMetrics(t *testing.T) {
	_, ps := load(t)
	known := map[string]bool{}
	for _, d := range gateway.MetricCatalog {
		known[d.Name] = true
	}
	re := regexp.MustCompile(`setura_gateway_[a-z0-9_]+`)
	n := 0
	for _, p := range ps {
		for _, tg := range p.Targets {
			for _, m := range re.FindAllString(tg.Expr, -1) {
				n++
				base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(m, "_bucket"), "_sum"), "_count")
				if !known[m] && !known[base] {
					t.Errorf("panel %q queries %s, which the gateway does not expose", p.Title, m)
				}
			}
		}
	}
	if n < 10 {
		t.Errorf("only %d metric references: the regexp is wrong", n)
	}
}
