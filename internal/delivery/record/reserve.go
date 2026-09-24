package record

import (
	"github.com/rebaze/rio/internal/delivery"
	"path/filepath"
	"sort"
)

// ReserveAll acquires absent paths in canonical order and returns ownership in
// caller order. A failed batch publishes no intents and releases every owned lock.
func ReserveAll(paths []string) (result []*Reservation, err error) {
	type pathIndex struct {
		path  string
		index int
	}
	order := make([]pathIndex, 0, len(paths))
	for i, p := range paths {
		abs, e := filepath.Abs(p)
		if e != nil {
			return nil, delivery.Fail("invalid_record_path", "record")
		}
		parent, e := filepath.EvalSymlinks(filepath.Dir(abs))
		if e != nil {
			return nil, delivery.Fail("invalid_record_path", "existing parent required")
		}
		order = append(order, pathIndex{filepath.Join(parent, filepath.Base(abs)), i})
	}
	sort.Slice(order, func(i, j int) bool { return order[i].path < order[j].path })
	owned := make([]*Reservation, len(paths))
	defer func() {
		if result == nil {
			for _, r := range owned {
				if r != nil {
					if e := r.Close(); e != nil {
						err = e
					}
				}
			}
		}
	}()
	for _, v := range order {
		r, e := Reserve(v.path)
		if e != nil {
			return nil, e
		}
		owned[v.index] = r
	}
	return owned, nil
}
