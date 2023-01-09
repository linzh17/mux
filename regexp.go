// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mux

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type routeRegexpOptions struct {
	strictSlash    bool
	useEncodedPath bool
}

type regexpType int

const (
	regexpTypePath regexpType = iota
	regexpTypeHost
	regexpTypePrefix
	regexpTypeQuery
)

// newRouteRegexp parses a route template and returns a routeRegexp,
// used to match a host, a path or a query string.
//
// It will extract named variables, assemble a regexp to be matched, create
// a "reverse" template to build URLs and compile regexps to validate variable
// values used in URL building.
//
// Previously we accepted only Python-like identifiers for variable
// names ([a-zA-Z_][a-zA-Z0-9_]*), but currently the only restriction is that
// name and pattern can't be empty, and names can't contain a colon.
func newRouteRegexp(tpl string, typ regexpType, options routeRegexpOptions) (*routeRegexp, error) {
	// Check if it is well-formed.
	//braceIndices判断{ }是否成对并且正确出现，idxs是'{' '}'在表达式tpl中的下标数组
	idxs, errBraces := braceIndices(tpl)
	if errBraces != nil {
		return nil, errBraces
	}
	// Backup the original.
	template := tpl
	// Now let's parse it.
	//默认匹配规则，当{}中没有匹配规则时则使用默认匹配规则 e.g {userid}
	//{userid:[0-9]+},这种就不需要使用默认匹配规则
	// 默认匹配路由路径
	defaultPattern := "[^/]+"
	if typ == regexpTypeQuery {
		defaultPattern = ".*"
	} else if typ == regexpTypeHost {
		defaultPattern = "[^.]+"
	}
	// Only match strict slash if not matching
	if typ != regexpTypePath {
		options.strictSlash = false
	}
	// Set a flag for strictSlash.
	endSlash := false
	if options.strictSlash && strings.HasSuffix(tpl, "/") {
		tpl = tpl[:len(tpl)-1]
		endSlash = true
	}
	//保存所需要提取的所有变量名称
	varsN := make([]string, len(idxs)/2)
	//保存对应变量的regexp规则
	varsR := make([]*regexp.Regexp, len(idxs)/2)
	pattern := bytes.NewBufferString("")
	pattern.WriteByte('^')
	reverse := bytes.NewBufferString("")
	// end }的索引位置
	var end int
	var err error
	for i := 0; i < len(idxs); i += 2 {
		// Set all values we are interested in.
		//e.g. tpl "/products/list/{index1}-{index2}"
		raw := tpl[end:idxs[i]] //"/products/list/" ，"-"
		end = idxs[i+1]

		// 对{}中的字符串根据进行分割 e.g {userid},{userid:[0-9]+}
		//parts 就是变量名以及正则表达式对
		parts := strings.SplitN(tpl[idxs[i]+1:end-1], ":", 2)
		//变量名称
		name := parts[0]
		//正则模式串
		patt := defaultPattern //[^/]+
		//如果part长度为2，则存在提供的正则模式串 e.g. {userid:[0-9]+} 中patt为[0-9]+
		if len(parts) == 2 {
			patt = parts[1]
		}
		// Name or pattern can't be empty.
		if name == "" || patt == "" {
			return nil, fmt.Errorf("mux: missing name or pattern in %q",
				tpl[idxs[i]:end])
		}
		// Build the regexp pattern.
		//QuoteMeta 将字符串 s 中的“特殊字符”转换为其“转义格式”
		// pattern e.g. "/products/list/(?P<v0>[^/]+)-(?P<v1>[^/]+)"
		// "%s(?P<%s>%s)" e.g. "/products/list/(?P<v0>[^/]+)","-(?P<v1>[^/]+)"
		fmt.Fprintf(pattern, "%s(?P<%s>%s)", regexp.QuoteMeta(raw), varGroupName(i/2), patt)

		// Build the reverse template.
		//"%s%%s" e.g. "products/list/%s","-%s"
		//reverse "products/list/%s-%s"
		fmt.Fprintf(reverse, "%s%%s", raw)

		// Append variable name and compiled pattern.
		varsN[i/2] = name
		varsR[i/2], err = regexp.Compile(fmt.Sprintf("^%s$", patt))
		if err != nil {
			return nil, err
		}
	}
	// Add the remaining.
	//路径剩余部分
	raw := tpl[end:]
	pattern.WriteString(regexp.QuoteMeta(raw))
	if options.strictSlash {
		pattern.WriteString("[/]?")
	}
	//query 参数匹配
	if typ == regexpTypeQuery {
		// Add the default pattern if the query value is empty
		if queryVal := strings.SplitN(template, "=", 2)[1]; queryVal == "" {
			pattern.WriteString(defaultPattern)
		}
	}
	//前缀匹配
	if typ != regexpTypePrefix {
		pattern.WriteByte('$')
	}

	var wildcardHostPort bool
	if typ == regexpTypeHost {
		if !strings.Contains(pattern.String(), ":") {
			wildcardHostPort = true
		}
	}
	// 路径剩余部分
	reverse.WriteString(raw)
	if endSlash {
		reverse.WriteByte('/')
	}
	// Compile full regexp.
	//完整匹配规则
	reg, errCompile := regexp.Compile(pattern.String())
	if errCompile != nil {
		return nil, errCompile
	}

	// Check for capturing groups which used to work in older versions
	if reg.NumSubexp() != len(idxs)/2 {
		panic(fmt.Sprintf("route %s contains capture groups in its regexp. ", template) +
			"Only non-capturing groups are accepted: e.g. (?:pattern) instead of (pattern)")
	}

	// Done!
	return &routeRegexp{
		template:         template,
		regexpType:       typ,
		options:          options,
		regexp:           reg,
		reverse:          reverse.String(),
		varsN:            varsN,
		varsR:            varsR,
		wildcardHostPort: wildcardHostPort,
	}, nil
}

// routeRegexp stores a regexp to match a host or path and information to
// collect and validate route variables.
type routeRegexp struct {
	// The unmodified template.
	template string
	// The type of match
	regexpType regexpType
	// Options for matching
	options routeRegexpOptions
	// Expanded regexp.
	regexp *regexp.Regexp
	// Reverse template.
	reverse string
	// Variable names.
	varsN []string
	// Variable regexps (validators).
	varsR []*regexp.Regexp
	// Wildcard host-port (no strict port match in hostname)
	wildcardHostPort bool
}

// Match matches the regexp against the URL host or path.
func (r *routeRegexp) Match(req *http.Request, match *RouteMatch) bool {
	if r.regexpType == regexpTypeHost {
		host := getHost(req)
		if r.wildcardHostPort {
			// Don't be strict on the port match
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
		}
		return r.regexp.MatchString(host)
	}

	if r.regexpType == regexpTypeQuery {
		return r.matchQueryString(req)
	}
	path := req.URL.Path
	if r.options.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	return r.regexp.MatchString(path)
}

// url builds a URL part using the given values.
func (r *routeRegexp) url(values map[string]string) (string, error) {
	urlValues := make([]interface{}, len(r.varsN), len(r.varsN))
	for k, v := range r.varsN {
		value, ok := values[v]
		if !ok {
			return "", fmt.Errorf("mux: missing route variable %q", v)
		}
		if r.regexpType == regexpTypeQuery {
			value = url.QueryEscape(value)
		}
		urlValues[k] = value
	}
	rv := fmt.Sprintf(r.reverse, urlValues...)
	if !r.regexp.MatchString(rv) {
		// The URL is checked against the full regexp, instead of checking
		// individual variables. This is faster but to provide a good error
		// message, we check individual regexps if the URL doesn't match.
		for k, v := range r.varsN {
			if !r.varsR[k].MatchString(values[v]) {
				return "", fmt.Errorf(
					"mux: variable %q doesn't match, expected %q", values[v],
					r.varsR[k].String())
			}
		}
	}
	return rv, nil
}

// getURLQuery returns a single query parameter from a request URL.
// For a URL with foo=bar&baz=ding, we return only the relevant key
// value pair for the routeRegexp.
func (r *routeRegexp) getURLQuery(req *http.Request) string {
	if r.regexpType != regexpTypeQuery {
		return ""
	}
	templateKey := strings.SplitN(r.template, "=", 2)[0]
	val, ok := findFirstQueryKey(req.URL.RawQuery, templateKey)
	if ok {
		return templateKey + "=" + val
	}
	return ""
}

// findFirstQueryKey returns the same result as (*url.URL).Query()[key][0].
// If key was not found, empty string and false is returned.
func findFirstQueryKey(rawQuery, key string) (value string, ok bool) {
	query := []byte(rawQuery)
	for len(query) > 0 {
		foundKey := query
		if i := bytes.IndexAny(foundKey, "&;"); i >= 0 {
			foundKey, query = foundKey[:i], foundKey[i+1:]
		} else {
			query = query[:0]
		}
		if len(foundKey) == 0 {
			continue
		}
		var value []byte
		if i := bytes.IndexByte(foundKey, '='); i >= 0 {
			foundKey, value = foundKey[:i], foundKey[i+1:]
		}
		if len(foundKey) < len(key) {
			// Cannot possibly be key.
			continue
		}
		keyString, err := url.QueryUnescape(string(foundKey))
		if err != nil {
			continue
		}
		if keyString != key {
			continue
		}
		valueString, err := url.QueryUnescape(string(value))
		if err != nil {
			continue
		}
		return valueString, true
	}
	return "", false
}

func (r *routeRegexp) matchQueryString(req *http.Request) bool {
	return r.regexp.MatchString(r.getURLQuery(req))
}

// braceIndices returns the first level curly brace indices from a string.
// It returns an error in case of unbalanced braces.
func braceIndices(s string) ([]int, error) {
	var level, idx int
	var idxs []int
	//level 用于记录最外层{}
	//判断{}是否成对出现，并记录每一对{}的idx位置。
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			if level++; level == 1 {
				idx = i
			}
		case '}':
			if level--; level == 0 {
				idxs = append(idxs, idx, i+1)
			} else if level < 0 {
				return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
			}
		}
	}
	if level != 0 {
		return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
	}
	return idxs, nil
}

// varGroupName builds a capturing group name for the indexed variable.
func varGroupName(idx int) string {
	return "v" + strconv.Itoa(idx)
}

// ----------------------------------------------------------------------------
// routeRegexpGroup
// ----------------------------------------------------------------------------

// routeRegexpGroup groups the route matchers that carry variables.
type routeRegexpGroup struct {
	host    *routeRegexp
	path    *routeRegexp
	queries []*routeRegexp
}

// setMatch extracts the variables from the URL once a route matches.
func (v routeRegexpGroup) setMatch(req *http.Request, m *RouteMatch, r *Route) {
	// Store host variables.
	if v.host != nil {
		host := getHost(req)
		if v.host.wildcardHostPort {
			// Don't be strict on the port match
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
		}
		matches := v.host.regexp.FindStringSubmatchIndex(host)
		if len(matches) > 0 {
			extractVars(host, matches, v.host.varsN, m.Vars)
		}
	}
	path := req.URL.Path
	if r.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	// Store path variables.
	if v.path != nil {
		//FindStringSubmatchIndex
		//查找 re 中编译好的正则表达式，并返回第一个匹配的位置
		// 同时返回子表达式匹配的位置
		// {完整项起始, 完整项结束, 子项起始, 子项结束, 子项起始, 子项结束, ...}
		matches := v.path.regexp.FindStringSubmatchIndex(path)
		if len(matches) > 0 {
			//提取Vars
			extractVars(path, matches, v.path.varsN, m.Vars)
			// Check if we should redirect.
			// 判断是否需要重定向
			if v.path.options.strictSlash {
				p1 := strings.HasSuffix(path, "/")
				p2 := strings.HasSuffix(v.path.template, "/")
				if p1 != p2 {
					u, _ := url.Parse(req.URL.String())
					if p1 {
						u.Path = u.Path[:len(u.Path)-1]
					} else {
						u.Path += "/"
					}
					m.Handler = http.RedirectHandler(u.String(), http.StatusMovedPermanently)
				}
			}
		}
	}
	// Store query string variables.
	for _, q := range v.queries {
		queryURL := q.getURLQuery(req)
		matches := q.regexp.FindStringSubmatchIndex(queryURL)
		if len(matches) > 0 {
			extractVars(queryURL, matches, q.varsN, m.Vars)
		}
	}
}

// getHost tries its best to return the request host.
// According to section 14.23 of RFC 2616 the Host header
// can include the port number if the default value of 80 is not used.
func getHost(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.Host
	}
	return r.Host
}

func extractVars(input string, matches []int, names []string, output map[string]string) {
	for i, name := range names {
		output[name] = input[matches[2*i+2]:matches[2*i+3]]
	}
}
