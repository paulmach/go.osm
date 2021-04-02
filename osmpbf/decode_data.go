package osmpbf

import (
	"errors"
	"time"

	"github.com/paulmach/osm"
	"github.com/paulmach/osm/osmpbf/internal/osmpbf"
	"github.com/paulmach/protoscan"
)

// dataDecoder is a decoder for Blob with OSMData (PrimitiveBlock).
type dataDecoder struct {
	scanner *Scanner
	data    []byte
	q       []osm.Object

	// cache objects to save allocations
	primitiveBlock *osmpbf.PrimitiveBlock

	keys, vals *protoscan.Iterator

	// ways
	nodes *protoscan.Iterator
	wlats *protoscan.Iterator
	wlons *protoscan.Iterator

	// relations
	roles  *protoscan.Iterator
	memids *protoscan.Iterator
	types  *protoscan.Iterator

	// dense nodes
	ids *protoscan.Iterator

	versions   *protoscan.Iterator
	timestamps *protoscan.Iterator
	changesets *protoscan.Iterator
	uids       *protoscan.Iterator
	usids      *protoscan.Iterator
	visibles   *protoscan.Iterator

	lats *protoscan.Iterator
	lons *protoscan.Iterator

	keyvals *protoscan.Iterator
}

func (dec *dataDecoder) Decode(blob *osmpbf.Blob) ([]osm.Object, error) {
	dec.q = make([]osm.Object, 0, 8000) // typical PrimitiveBlock contains 8k OSM entities

	var err error
	dec.data, err = getData(blob, dec.data)
	if err != nil {
		return nil, err
	}

	err = dec.scanPrimitiveBlock(dec.data)
	if err != nil {
		return nil, err
	}
	return dec.q, nil
}

func (dec *dataDecoder) scanPrimitiveBlock(data []byte) error {
	msg := protoscan.New(data)

	if dec.primitiveBlock == nil {
		dec.primitiveBlock = &osmpbf.PrimitiveBlock{
			Stringtable: &osmpbf.StringTable{},
		}
	} else {
		dec.primitiveBlock.Stringtable.S = dec.primitiveBlock.Stringtable.S[:0]
		dec.primitiveBlock.Primitivegroup = dec.primitiveBlock.Primitivegroup[:0]
		dec.primitiveBlock.Granularity = nil
		dec.primitiveBlock.LatOffset = nil
		dec.primitiveBlock.LonOffset = nil
		dec.primitiveBlock.DateGranularity = nil
	}

	for msg.Next() {
		switch msg.FieldNumber() {
		case 1:
			d, err := msg.MessageData()
			if err != nil {
				return err
			}
			err = dec.primitiveBlock.Stringtable.Unmarshal(d)
			if err != nil {
				return err
			}
		case 17:
			v, err := msg.Int32()
			dec.primitiveBlock.Granularity = &v
			if err != nil {
				return err
			}
		case 18:
			v, err := msg.Int32()
			dec.primitiveBlock.DateGranularity = &v
			if err != nil {
				return err
			}
		case 19:
			v, err := msg.Int64()
			dec.primitiveBlock.LatOffset = &v
			if err != nil {
				return err
			}
		case 20:
			v, err := msg.Int64()
			dec.primitiveBlock.LonOffset = &v
			if err != nil {
				return err
			}
		default:
			msg.Skip()
		}
	}

	if msg.Err() != nil {
		return msg.Err()
	}

	// we need the offsets and granularities for the group decoding

	msg.Reset(nil)
	for msg.Next() {
		switch msg.FieldNumber() {
		case 2:
			d, err := msg.MessageData()
			if err != nil {
				return err
			}
			err = dec.scanPrimitiveGroup(d)
			if err != nil {
				return err
			}
		default:
			msg.Skip()
		}
	}

	return msg.Err()
}

func (dec *dataDecoder) scanPrimitiveGroup(data []byte) error {
	msg := protoscan.New(data)

	for msg.Next() {
		fn := msg.FieldNumber()
		if fn == 1 {
			panic("nodes are not supported, currently untested")
		}

		if fn == 2 && !dec.scanner.SkipNodes {
			data, err := msg.MessageData()
			if err != nil {
				return err
			}

			err = dec.scanDenseNodes(data)
			if err != nil {
				return err
			}

			continue
		}

		if fn == 3 && !dec.scanner.SkipWays {
			data, err := msg.MessageData()
			if err != nil {
				return err
			}

			err = dec.scanWays(data)
			if err != nil {
				return err
			}

			continue
		}

		if fn == 4 && !dec.scanner.SkipRelations {
			data, err := msg.MessageData()
			if err != nil {
				return err
			}

			err = dec.scanRelations(data)
			if err != nil {
				return err
			}

			continue
		}

		msg.Skip()
	}

	return msg.Err()
}

func (dec *dataDecoder) scanDenseNodes(data []byte) error {
	var foundIds, foundInfo, foundLats, foundLons, foundKeyVals bool

	msg := protoscan.New(data)
	for msg.Next() {
		var err error
		switch msg.FieldNumber() {
		case 1: // ids
			dec.ids, err = msg.Iterator(dec.ids)
			foundIds = true
		case 5: // dense info
			d, err := msg.MessageData()
			if err != nil {
				return err
			}

			// verify all the fields are "found" since we reuse object from last block
			// and can't just check for nil
			var foundVersions, foundTimestamps, foundChangesets,
				foundUids, foundUsids, foundVisibles bool

			info := protoscan.New(d)
			for info.Next() {
				var err error
				switch info.FieldNumber() {
				case 1: // version
					dec.versions, err = info.Iterator(dec.versions)
					foundVersions = true
				case 2: // timestamp
					dec.timestamps, err = info.Iterator(dec.timestamps)
					foundTimestamps = true
				case 3: // changeset
					dec.changesets, err = info.Iterator(dec.changesets)
					foundChangesets = true
				case 4: // uid
					dec.uids, err = info.Iterator(dec.uids)
					foundUids = true
				case 5: // user_sid
					dec.usids, err = info.Iterator(dec.usids)
					foundUsids = true
				case 6: // visible, optional, default true
					dec.visibles, err = info.Iterator(dec.visibles)
					foundVisibles = true
				default:
					info.Skip()
				}

				if err != nil {
					return err
				}
			}

			if info.Err() != nil {
				return info.Err()
			}

			// visibles are optional, default is true
			if !foundVisibles {
				dec.visibles = nil
			}

			if !foundVersions || !foundTimestamps || !foundChangesets || !foundUids || !foundUsids {
				return errors.New("dense node does not include all required fields")
			}

			foundInfo = true
		case 8: // lat
			dec.lats, err = msg.Iterator(dec.lats)
			foundLats = true
		case 9: // lon
			dec.lons, err = msg.Iterator(dec.lons)
			foundLons = true
		case 10: // keys_vals
			dec.keyvals, err = msg.Iterator(dec.keyvals)
			foundKeyVals = true
		default:
			msg.Skip()
		}

		if err != nil {
			return err
		}
	}

	if msg.Err() != nil {
		return msg.Err()
	}

	// keyvals could be empty if all nodes are tagless
	if !foundKeyVals {
		dec.keyvals = nil
	}

	if !foundIds || !foundInfo || !foundLats || !foundLons {
		return errors.New("dense node does not include all required fields")
	}

	return dec.extractDenseNodes()
}

func (dec *dataDecoder) extractDenseNodes() error {
	st := dec.primitiveBlock.GetStringtable().GetS()
	granularity := int64(dec.primitiveBlock.GetGranularity())
	dateGranularity := int64(dec.primitiveBlock.GetDateGranularity())

	latOffset := dec.primitiveBlock.GetLatOffset()
	lonOffset := dec.primitiveBlock.GetLonOffset()

	// we also assume all the iterators have the same length....

	nodes := make([]osm.Node, dec.versions.Count(protoscan.WireTypeVarint))

	var id, lat, lon, timestamp, changeset int64
	var uid, usid int32
	var index int
	for dec.versions.HasNext() {
		n := &nodes[index]
		n.Visible = true

		// ID
		v1, err := dec.ids.Sint64()
		if err != nil {
			return err
		}
		id += v1
		n.ID = osm.NodeID(id)

		// Version
		v2, err := dec.versions.Int32()
		if err != nil {
			return err
		}
		n.Version = int(v2)

		// Timestamp
		v3, err := dec.timestamps.Sint64()
		if err != nil {
			return err
		}
		timestamp += v3
		millisec := time.Duration(timestamp*dateGranularity) * time.Millisecond
		n.Timestamp = time.Unix(0, millisec.Nanoseconds()).UTC()

		// Changeset
		v4, err := dec.changesets.Sint64()
		if err != nil {
			return err
		}
		changeset += v4
		n.ChangesetID = osm.ChangesetID(changeset)

		// uid
		v5, err := dec.uids.Sint32()
		if err != nil {
			return err
		}
		uid += v5
		n.UserID = osm.UserID(uid)

		// usid
		v6, err := dec.usids.Sint32()
		if err != nil {
			return err
		}
		usid += v6
		n.User = st[usid]

		// Visible
		if dec.visibles != nil {
			v7, err := dec.visibles.Bool()
			if err != nil {
				return err
			}
			n.Visible = v7
		}

		// lat
		v8, err := dec.lats.Sint64()
		if err != nil {
			return err
		}
		lat += v8
		n.Lat = 1e-9 * float64(latOffset+(granularity*lat))

		// lon
		v9, err := dec.lons.Sint64()
		if err != nil {
			return err
		}
		lon += v9
		n.Lon = 1e-9 * float64(lonOffset+(granularity*lon))

		// tags, could be missing if all nodes are tagless
		if dec.keyvals != nil {
			// TODO: precompute length of tags to preallocate
			for {
				k, err := dec.keyvals.Int32()
				if err != nil {
					return err
				}

				if k == 0 {
					break
				}

				v, err := dec.keyvals.Int32()
				if err != nil {
					return err
				}

				n.Tags = append(n.Tags, osm.Tag{Key: st[k], Value: st[v]})
			}
		}
		if dec.scanner.SkipNodeFunction == nil || !dec.scanner.SkipNodeFunction(*n) {
			// skip unwanted nodes
			index++
		}
	}
	/* copy to an array just large enough */
	tmp := make([]osm.Node, index)
	copy(tmp, nodes)
	for i := range tmp {
		dec.q = append(dec.q, &tmp[i])
	}
	return nil
}

func (dec *dataDecoder) scanWays(data []byte) error {
	st := dec.primitiveBlock.GetStringtable().GetS()
	granularity := int64(dec.primitiveBlock.GetGranularity())
	dateGranularity := int64(dec.primitiveBlock.GetDateGranularity())

	latOffset := dec.primitiveBlock.GetLatOffset()
	lonOffset := dec.primitiveBlock.GetLonOffset()

	msg := protoscan.New(data)

	way := &osm.Way{Visible: true}
	var foundKeys, foundVals bool
	for msg.Next() {
		var i64 int64
		var err error

		switch msg.FieldNumber() {
		case 1:
			i64, err = msg.Int64()
			way.ID = osm.WayID(i64)
		case 2:
			dec.keys, err = msg.Iterator(dec.keys)
			foundKeys = true
		case 3:
			dec.vals, err = msg.Iterator(dec.vals)
			foundVals = true
		case 4: // info
			d, err := msg.MessageData()
			if err != nil {
				return err
			}

			info := protoscan.New(d)
			for info.Next() {
				switch info.FieldNumber() {
				case 1:
					v, err := info.Int32()
					if err != nil {
						return err
					}
					way.Version = int(v)
				case 2:
					v, err := info.Int64()
					if err != nil {
						return err
					}
					millisec := time.Duration(v*dateGranularity) * time.Millisecond
					way.Timestamp = time.Unix(0, millisec.Nanoseconds()).UTC()
				case 3:
					v, err := info.Int64()
					if err != nil {
						return err
					}
					way.ChangesetID = osm.ChangesetID(v)
				case 4:
					v, err := info.Int32()
					if err != nil {
						return err
					}
					way.UserID = osm.UserID(v)
				case 5:
					v, err := info.Uint32()
					if err != nil {
						return err
					}
					way.User = st[v]
				case 6:
					v, err := info.Bool()
					if err != nil {
						return err
					}
					way.Visible = v
				default:
					info.Skip()
				}
			}

			if info.Err() != nil {
				return info.Err()
			}
		case 8: // refs or nodes
			dec.nodes, err = msg.Iterator(dec.nodes)
			if err != nil {
				return err
			}

			var prev, index int64
			if len(way.Nodes) == 0 {
				way.Nodes = make(osm.WayNodes, dec.nodes.Count(protoscan.WireTypeVarint))
			}
			for dec.nodes.HasNext() {
				v, err := dec.nodes.Sint64()
				if err != nil {
					return err
				}
				prev = v + prev // delta encoding
				way.Nodes[index].ID = osm.NodeID(prev)
				index++
			}
		case 9: // lat
			dec.wlats, err = msg.Iterator(dec.wlats)
			if err != nil {
				return err
			}

			var prev, index int64
			if len(way.Nodes) == 0 {
				way.Nodes = make(osm.WayNodes, dec.wlats.Count(protoscan.WireTypeVarint))
			}
			for dec.wlats.HasNext() {
				v, err := dec.wlats.Sint64()
				if err != nil {
					return err
				}
				prev = v + prev // delta encoding
				way.Nodes[index].Lat = 1e-9 * float64(latOffset+(granularity*prev))
				index++
			}
		case 10: // lon
			dec.wlons, err = msg.Iterator(dec.wlons)
			if err != nil {
				return err
			}

			var prev, index int64
			if len(way.Nodes) == 0 {
				way.Nodes = make(osm.WayNodes, dec.wlons.Count(protoscan.WireTypeVarint))
			}
			for dec.wlons.HasNext() {
				v, err := dec.wlons.Sint64()
				if err != nil {
					return err
				}
				prev = v + prev // delta encoding
				way.Nodes[index].Lon = 1e-9 * float64(lonOffset+(granularity*prev))
				index++
			}
		default:
			msg.Skip()
		}

		if err != nil {
			return err
		}
	}

	if msg.Err() != nil {
		return msg.Err()
	}

	if foundKeys && foundVals {
		var err error
		way.Tags, err = scanTags(st, dec.keys, dec.vals)
		if err != nil {
			return err
		}
	}

	dec.q = append(dec.q, way)
	return nil
}

// Make relation members from stringtable and three parallel arrays of IDs.
func extractMembers(
	st []string,
	roles *protoscan.Iterator,
	memids *protoscan.Iterator,
	types *protoscan.Iterator,
) (osm.Members, error) {
	var index, memID int64

	members := make(osm.Members, types.Count(protoscan.WireTypeVarint))
	for roles.HasNext() {
		r, err := roles.Int32()
		if err != nil {
			return nil, err
		}
		members[index].Role = st[r]

		m, err := memids.Sint64()
		if err != nil {
			return nil, err
		}
		memID += m
		members[index].Ref = memID

		t, err := types.Int32()
		if err != nil {
			return nil, err
		}

		switch osmpbf.Relation_MemberType(t) {
		case osmpbf.Relation_NODE:
			members[index].Type = osm.TypeNode
		case osmpbf.Relation_WAY:
			members[index].Type = osm.TypeWay
		case osmpbf.Relation_RELATION:
			members[index].Type = osm.TypeRelation
		}

		index++
	}

	return members, nil
}

func (dec *dataDecoder) scanRelations(data []byte) error {
	st := dec.primitiveBlock.GetStringtable().GetS()
	dateGranularity := int64(dec.primitiveBlock.GetDateGranularity())

	msg := protoscan.New(data)

	relation := &osm.Relation{Visible: true}
	var foundKeys, foundVals, foundRoles, foundMemids, foundTypes bool
	for msg.Next() {
		var i64 int64
		var err error

		switch msg.FieldNumber() {
		case 1:
			i64, err = msg.Int64()
			relation.ID = osm.RelationID(i64)
		case 2:
			dec.keys, err = msg.Iterator(dec.keys)
			foundKeys = true
		case 3:
			dec.vals, err = msg.Iterator(dec.vals)
			foundVals = true
		case 4: // info
			d, err := msg.MessageData()
			if err != nil {
				return err
			}

			info := protoscan.New(d)
			for info.Next() {
				switch info.FieldNumber() {
				case 1:
					v, err := info.Int32()
					if err != nil {
						return err
					}
					relation.Version = int(v)
				case 2:
					v, err := info.Int64()
					if err != nil {
						return err
					}
					millisec := time.Duration(v*dateGranularity) * time.Millisecond
					relation.Timestamp = time.Unix(0, millisec.Nanoseconds()).UTC()
				case 3:
					v, err := info.Int64()
					if err != nil {
						return err
					}
					relation.ChangesetID = osm.ChangesetID(v)
				case 4:
					v, err := info.Int32()
					if err != nil {
						return err
					}
					relation.UserID = osm.UserID(v)
				case 5:
					v, err := info.Uint32()
					if err != nil {
						return err
					}
					relation.User = st[v]
				case 6:
					v, err := info.Bool()
					if err != nil {
						return err
					}
					relation.Visible = v
				default:
					info.Skip()
				}
			}

			if info.Err() != nil {
				return info.Err()
			}
		case 8: // refs or nodes
			dec.roles, err = msg.Iterator(dec.roles)
			foundRoles = true
		case 9:
			dec.memids, err = msg.Iterator(dec.memids)
			foundMemids = true
		case 10:
			dec.types, err = msg.Iterator(dec.types)
			foundTypes = true
		default:
			msg.Skip()
		}

		if err != nil {
			return err
		}
	}

	if msg.Err() != nil {
		return msg.Err()
	}

	// possible for relation to not have tags
	if foundKeys && foundVals {
		var err error
		relation.Tags, err = scanTags(st, dec.keys, dec.vals)
		if err != nil {
			return err
		}
	}

	// possible for relation to not have any members
	if foundRoles && foundMemids && foundTypes {
		var err error
		relation.Members, err = extractMembers(st, dec.roles, dec.memids, dec.types)
		if err != nil {
			return err
		}
	}

	dec.q = append(dec.q, relation)
	return nil
}

func scanTags(stringTable []string, keys, vals *protoscan.Iterator) (osm.Tags, error) {
	// note we assume keys and vals are the same length
	// we also assume index are within range of the stringTable

	index := 0
	tags := make(osm.Tags, keys.Count(protoscan.WireTypeVarint))
	for keys.HasNext() {
		k, err := keys.Uint32()
		if err != nil {
			return nil, err
		}
		v, err := vals.Uint32()
		if err != nil {
			return nil, err
		}
		tags[index] = osm.Tag{
			Key:   stringTable[k],
			Value: stringTable[v],
		}
		index++
	}

	return tags, nil
}
