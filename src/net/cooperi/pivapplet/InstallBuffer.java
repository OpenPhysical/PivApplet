package net.cooperi.pivapplet;

import javacard.framework.Util;

public class InstallBuffer implements Readable {
    byte[] params;
    short bufferOffset;
    byte length;

    public InstallBuffer (byte[] installParams, short installOffset, byte installLength) {
        params = installParams;
        bufferOffset = installOffset;
        length = installLength;
    }

    @Override
    public boolean atEnd() {
        return false;
    }

    // How many bytes are available to read?
    @Override
    public short available() {
        return length < (short)(params.length - bufferOffset) ? length : (short)(params.length - bufferOffset);
    }

    @Override
    public byte readByte() {
        return params[bufferOffset++];
    }

    @Override
    public short readShort() {
        return 0;
    }

    @Override
    public short read(byte[] dest, short offset, short maxLen) {
        short copied = (short)(Util.arrayCopy(params, bufferOffset, dest, offset, maxLen) - offset);
        bufferOffset += copied;
        return copied;
    }

    @Override
    public short read(TransientBuffer into, short maxLen) {
        return 0;
    }

    @Override
    public short readPartial(TransientBuffer into, short maxLen) {
        return 0;
    }

    @Override
    public void skip(short len) {

    }

    @Override
    public void rewind() {

    }
}
