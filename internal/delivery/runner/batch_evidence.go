package runner

import (
	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/delivery/batchrecord"
)

// BatchCompletion retains only safe runner assertions. Raw error messages and
// live clients cannot enter the immutable completion source.
func BatchCompletion(d batchrecord.Descriptor, raw []byte, r BatchResult) (batchrecord.Completion, error) {
	c := batchrecord.Completion{SchemaVersion: 1, Kind: "rio-delivery-batch-result", BatchSHA256: delivery.Digest(raw), Outcome: r.Outcome, RequestMayHaveOccurred: r.RequestMayHaveOccurred, Items: []batchrecord.CompletionItem{}}
	if r.Error != nil {
		c.ErrorCode = r.Error.Code
	}
	if len(r.Items) != len(d.Pairs) {
		return c, delivery.Fail("invalid_batch_evidence", "completion membership")
	}
	for i, item := range r.Items {
		p := d.Pairs[i]
		if item.ArtifactID != p.ArtifactID || item.Target != p.Target || item.Record != p.JournalPathHint {
			return c, delivery.Fail("invalid_batch_evidence", "completion pair")
		}
		value := batchrecord.CompletionItem{PairID: p.ID, State: item.State}
		if item.Error != nil {
			value.ErrorCode = item.Error.Code
		}
		if item.Result != nil {
			value.AttemptID = item.Result.AttemptID
			value.Acknowledgment = item.Result.Acknowledgment
			value.RequestMayHaveOccurred = item.Result.RequestMayHaveOccurred
		}
		c.Items = append(c.Items, value)
	}
	return c, batchrecord.ValidateCompletion(c, d, raw)
}
