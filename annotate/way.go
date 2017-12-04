package annotate

import (
	"context"
	"time"

	"github.com/paulmach/osm"
	"github.com/paulmach/osm/annotate/internal/core"
)

// NodeHistoryDatasourcer is an more strict interface for when we only need node history.
type NodeHistoryDatasourcer interface {
	NodeHistory(context.Context, osm.NodeID) (osm.Nodes, error)
	NotFound(error) bool
}

var _ NodeHistoryDatasourcer = &osm.HistoryDatasource{}

// Ways computes the updates for the given ways
// and annotate the way nodes with changeset and lon/lat data.
// The input ways are modified to include this information.
func Ways(
	ctx context.Context,
	ways osm.Ways,
	datasource NodeHistoryDatasourcer,
	threshold time.Duration,
	opts ...Option,
) error {
	computeOpts := &core.Options{}
	for _, o := range opts {
		err := o(computeOpts)
		if err != nil {
			return err
		}
	}
	computeOpts.Threshold = threshold

	parents := make([]core.Parent, len(ways))
	for i, w := range ways {
		parents[i] = &parentWay{Way: w}
	}

	wds := &wayDatasource{datasource}
	updatesForParents, err := core.Compute(ctx, parents, wds, computeOpts)
	if err != nil {
		return mapErrors(err)
	}

	// fill in updates
	for i, updates := range updatesForParents {
		ways[i].Updates = updates
	}

	return nil
}

// A parentWay wraps a osm.Way into the core.Parent interface
// so that updates can be computed.
type parentWay struct {
	Way      *osm.Way
	children core.ChildList
	refs     osm.FeatureIDs
}

func (w parentWay) ID() osm.FeatureID {
	return w.Way.FeatureID()
}

func (w parentWay) ChangesetID() osm.ChangesetID {
	return w.Way.ChangesetID
}

func (w parentWay) Version() int {
	return w.Way.Version
}

func (w parentWay) Visible() bool {
	return w.Way.Visible
}

func (w parentWay) Timestamp() time.Time {
	return w.Way.Timestamp
}

func (w parentWay) Committed() time.Time {
	if w.Way.Committed == nil {
		return time.Time{}
	}

	return *w.Way.Committed
}

func (w parentWay) Refs() osm.FeatureIDs {
	if w.refs == nil {
		w.refs = w.Way.Nodes.FeatureIDs()
	}

	return w.refs
}

func (w parentWay) Children() core.ChildList {
	return w.children
}

func (w *parentWay) SetChildren(list core.ChildList) {
	w.children = list

	// copy back in the node information
	for i, child := range list {
		if child == nil {
			continue
		}

		n := child.(*childNode).Node

		w.Way.Nodes[i].Version = n.Version
		w.Way.Nodes[i].ChangesetID = n.ChangesetID
		w.Way.Nodes[i].Lat = n.Lat
		w.Way.Nodes[i].Lon = n.Lon
	}
}
