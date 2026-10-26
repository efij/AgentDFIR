package endpoint

import (
	"strconv"
	"strings"
	"time"
)

// Container-runtime event logs: what the daemon was asked to do with
// each container. Kind container, Operation "<runtime> <action>".
//
//	docker events --format '{{json .}}'
//	  {"Type":"container","Action":"exec_start: sh -c id","Actor":{"ID":"…",
//	   "Attributes":{"image":"alpine:3.19","name":"web","execID":"…"}},
//	   "time":1792922400,"timeNano":1792922400123456789}
//	podman events --format json
//	  {"ID":"…","Image":"…","Name":"web","Status":"start","Time":"…","Type":"container"}
//
// docker exec events carry the command run inside the container (after
// "exec_create: " / "exec_start: ", or in an exec command attribute);
// those records corroborate a claimed `docker exec …` like a process
// record. The daemon sees only its own API calls, so these records are
// sightings. Events about images, networks, volumes and the daemon are
// counted as UNSUPPORTED (only container events are mapped);
// health_status events are counted as skipped noise.
// containerd (`ctr events`) and CRI-O print text, not JSON: not read.

func loadDockerEvents(path string) (*LoadResult, error) {
	res := &LoadResult{}
	unsup := unsupportedCounter{}
	err := forEachJSONDoc(path, res, nil, func(doc map[string]any, ref string) {
		action := firstNonEmpty(leaf(doc, "Action"), leaf(doc, "status"))
		typ := strings.ToLower(firstNonEmpty(leaf(doc, "Type"), "container"))
		if action == "" {
			res.problem(ref + ": not a docker event (no Action)")
			return
		}
		if typ != "container" {
			unsup.add(res, "docker "+typ+" event")
			return
		}
		if strings.HasPrefix(action, "health_status") {
			res.ignore()
			return
		}
		var t time.Time
		if ns, err := strconv.ParseInt(leaf(doc, "timeNano"), 10, 64); err == nil && ns > 0 {
			t = time.Unix(0, ns).UTC()
		} else if tt, ok := parseTime(leaf(doc, "time")); ok {
			t = tt
		} else {
			res.problem(ref + ": no recognizable time")
			return
		}
		attrs, _ := dig(doc, "Actor.Attributes").(map[string]any)
		verb, cmd, _ := strings.Cut(action, ": ")
		r := Record{Time: t, Kind: "container", Source: "docker-events", Ref: ref, Operation: "docker " + strings.TrimSpace(verb),
			ContainerID:    normContainerID(firstNonEmpty(leaf(doc, "Actor.ID"), leaf(doc, "id"))),
			ContainerName:  anyStr(attrs["name"]),
			ContainerImage: firstNonEmpty(anyStr(attrs["image"]), leaf(doc, "from")),
			Pod:            anyStr(attrs["io.kubernetes.pod.name"]),
			K8sNamespace:   anyStr(attrs["io.kubernetes.pod.namespace"]),
		}
		if strings.HasPrefix(verb, "exec_") {
			r.Cmdline = strings.TrimSpace(firstNonEmpty(cmd, anyStr(attrs["execCommand"]), anyStr(attrs["exec_command"])))
			r.Exe = firstField(r.Cmdline)
		}
		if c := anyStr(attrs["exitCode"]); c != "" && c != "0" {
			r.Failed = "exit code " + c
		}
		if s := anyStr(attrs["signal"]); s != "" {
			r.Resource = "signal " + s
		}
		res.Records = append(res.Records, r)
	})
	unsup.flush(res, "only container events are mapped")
	return res, err
}

func loadPodmanEvents(path string) (*LoadResult, error) {
	res := &LoadResult{}
	unsup := unsupportedCounter{}
	err := forEachJSONDoc(path, res, nil, func(doc map[string]any, ref string) {
		status, typ := leaf(doc, "Status"), strings.ToLower(leaf(doc, "Type"))
		if status == "" || typ == "" {
			res.problem(ref + ": not a podman event (no Status/Type)")
			return
		}
		if typ != "container" {
			unsup.add(res, "podman "+typ+" event")
			return
		}
		if status == "health_status" {
			res.ignore()
			return
		}
		t, ok := parseTime(leaf(doc, "Time"))
		if !ok {
			if ns, err := strconv.ParseInt(leaf(doc, "timeNano"), 10, 64); err == nil && ns > 0 {
				t, ok = time.Unix(0, ns).UTC(), true
			}
		}
		if !ok {
			res.problem(ref + ": no recognizable time")
			return
		}
		r := Record{Time: t, Kind: "container", Source: "podman-events", Ref: ref, Operation: "podman " + status,
			ContainerID: normContainerID(leaf(doc, "ID")), ContainerName: leaf(doc, "Name"), ContainerImage: leaf(doc, "Image"),
			Pod: leaf(doc, "PodName")}
		if c := leaf(doc, "ContainerExitCode"); c != "" && c != "0" {
			r.Failed = "exit code " + c
		}
		res.Records = append(res.Records, r)
	})
	unsup.flush(res, "only container events are mapped")
	return res, err
}
