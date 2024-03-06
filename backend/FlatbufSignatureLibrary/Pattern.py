# automatically generated by the FlatBuffers compiler, do not modify

# namespace: FlatbufSignatureLibrary

import flatbuffers

class Pattern(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAsPattern(cls, buf, offset):  # type: ignore
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Pattern()
        x.Init(buf, n + offset)
        return x

    # Pattern
    def Init(self, buf, pos):  # type: ignore
        self._tab = flatbuffers.table.Table(buf, pos)

    # Pattern
    def Data(self, j):  # type: ignore
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 1))
        return 0

    # Pattern
    def DataAsNumpy(self):  # type: ignore
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint8Flags, o)
        return 0

    # Pattern
    def DataLength(self):  # type: ignore
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Pattern
    def Mask(self, j):  # type: ignore
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 1))
        return 0

    # Pattern
    def MaskAsNumpy(self):  # type: ignore
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint8Flags, o)
        return 0

    # Pattern
    def MaskLength(self):  # type: ignore
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

def PatternStart(builder): builder.StartObject(2)  # type: ignore
def PatternAddData(builder, data): builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(data), 0)  # type: ignore
def PatternStartDataVector(builder, numElems): return builder.StartVector(1, numElems, 1)  # type: ignore
def PatternAddMask(builder, mask): builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(mask), 0)  # type: ignore
def PatternStartMaskVector(builder, numElems): return builder.StartVector(1, numElems, 1)  # type: ignore
def PatternEnd(builder): return builder.EndObject()  # type: ignore
