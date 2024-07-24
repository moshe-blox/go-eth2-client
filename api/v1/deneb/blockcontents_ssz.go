// Code generated by fastssz. DO NOT EDIT.
// Hash: ff9e35462a2b6f51ea9d2ba948e74ce9d515869af12f466319130a4655751296
// Version: 0.1.3
package deneb

import (
	"github.com/attestantio/go-eth2-client/spec/deneb"
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the BlockContents object
func (b *BlockContents) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(b)
}

// MarshalSSZTo ssz marshals the BlockContents object to a target array
func (b *BlockContents) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Offset (0) 'Block'
	dst = ssz.WriteOffset(dst, offset)
	if b.Block == nil {
		b.Block = new(deneb.BeaconBlock)
	}
	offset += b.Block.SizeSSZ()

	// Offset (1) 'KZGProofs'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(b.KZGProofs) * 48

	// Offset (2) 'Blobs'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(b.Blobs) * 131072

	// Field (0) 'Block'
	if dst, err = b.Block.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (1) 'KZGProofs'
	if size := len(b.KZGProofs); size > 6 {
		err = ssz.ErrListTooBigFn("BlockContents.KZGProofs", size, 6)
		return
	}
	for ii := 0; ii < len(b.KZGProofs); ii++ {
		dst = append(dst, b.KZGProofs[ii][:]...)
	}

	// Field (2) 'Blobs'
	if size := len(b.Blobs); size > 6 {
		err = ssz.ErrListTooBigFn("BlockContents.Blobs", size, 6)
		return
	}
	for ii := 0; ii < len(b.Blobs); ii++ {
		dst = append(dst, b.Blobs[ii][:]...)
	}

	return
}

// UnmarshalSSZ ssz unmarshals the BlockContents object
func (b *BlockContents) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1, o2 uint64

	// Offset (0) 'Block'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 12 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'KZGProofs'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Offset (2) 'Blobs'
	if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (0) 'Block'
	{
		buf = tail[o0:o1]
		if b.Block == nil {
			b.Block = new(deneb.BeaconBlock)
		}
		if err = b.Block.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (1) 'KZGProofs'
	{
		buf = tail[o1:o2]
		num, err := ssz.DivideInt2(len(buf), 48, 6)
		if err != nil {
			return err
		}
		b.KZGProofs = make([]deneb.KZGProof, num)
		for ii := 0; ii < num; ii++ {
			copy(b.KZGProofs[ii][:], buf[ii*48:(ii+1)*48])
		}
	}

	// Field (2) 'Blobs'
	{
		buf = tail[o2:]
		num, err := ssz.DivideInt2(len(buf), 131072, 6)
		if err != nil {
			return err
		}
		b.Blobs = make([]deneb.Blob, num)
		for ii := 0; ii < num; ii++ {
			copy(b.Blobs[ii][:], buf[ii*131072:(ii+1)*131072])
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the BlockContents object
func (b *BlockContents) SizeSSZ() (size int) {
	size = 12

	// Field (0) 'Block'
	if b.Block == nil {
		b.Block = new(deneb.BeaconBlock)
	}
	size += b.Block.SizeSSZ()

	// Field (1) 'KZGProofs'
	size += len(b.KZGProofs) * 48

	// Field (2) 'Blobs'
	size += len(b.Blobs) * 131072

	return
}

// HashTreeRoot ssz hashes the BlockContents object
func (b *BlockContents) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(b)
}

// HashTreeRootWith ssz hashes the BlockContents object with a hasher
func (b *BlockContents) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Block'
	if err = b.Block.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'KZGProofs'
	{
		if size := len(b.KZGProofs); size > 6 {
			err = ssz.ErrListTooBigFn("BlockContents.KZGProofs", size, 6)
			return
		}
		subIndx := hh.Index()
		for _, i := range b.KZGProofs {
			hh.PutBytes(i[:])
		}
		numItems := uint64(len(b.KZGProofs))
		hh.MerkleizeWithMixin(subIndx, numItems, 6)
	}

	// Field (2) 'Blobs'
	{
		if size := len(b.Blobs); size > 6 {
			err = ssz.ErrListTooBigFn("BlockContents.Blobs", size, 6)
			return
		}
		subIndx := hh.Index()
		for _, i := range b.Blobs {
			hh.PutBytes(i[:])
		}
		numItems := uint64(len(b.Blobs))
		hh.MerkleizeWithMixin(subIndx, numItems, 6)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the BlockContents object
func (b *BlockContents) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(b)
}
