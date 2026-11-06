package com.signingflow;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public final class Jail {
    public static final int MAX_BYTES = 25 * 1024 * 1024;

    private Jail() {}

    public static byte[] read(String uploadRoot, String requested) throws SigningflowException.InvalidRequestException {
        return read(uploadRoot, requested, MAX_BYTES);
    }

    public static byte[] read(String uploadRoot, String requested, int maxBytes) throws SigningflowException.InvalidRequestException {
        if (uploadRoot == null || uploadRoot.isBlank()) {
            throw new SigningflowException.InvalidRequestException("A filesystem path requires upload_root.");
        }
        try {
            return readJailed(uploadRoot, requested == null ? "" : requested, maxBytes);
        } catch (InvalidPathException | IOException ex) {
            throw new SigningflowException.InvalidRequestException("The file could not be read.");
        }
    }

    private static byte[] readJailed(String rootText, String requested, int maxBytes) throws IOException, SigningflowException.InvalidRequestException {
        if (requested.isEmpty() || requested.indexOf('\0') >= 0) {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        Path requestedPath;
        try {
            requestedPath = Path.of(requested);
        } catch (InvalidPathException ex) {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        if (requestedPath.isAbsolute()) {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        for (Path segment : requestedPath) {
            if ("..".equals(segment.toString())) {
                throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
            }
        }
        Path root = Path.of(rootText).toRealPath();
        Path resolved = root.resolve(requested).normalize();
        if (!resolved.startsWith(root) || resolved.equals(root)) {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        Path parent = resolved.getParent();
        if (parent == null) {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        Path parentReal = parent.toRealPath();
        if (!parentReal.startsWith(root)) {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        Path leaf = parentReal.resolve(resolved.getFileName());
        if (!leaf.startsWith(root) || Files.isSymbolicLink(leaf)) {
            throw new SigningflowException.InvalidRequestException(Files.isSymbolicLink(leaf) ? "The file could not be read." : "The path is outside upload_root.");
        }
        if (!Files.isRegularFile(leaf, LinkOption.NOFOLLOW_LINKS)) {
            throw new SigningflowException.InvalidRequestException("The file could not be read.");
        }
        Object nlink = Files.getAttribute(leaf, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
        if (!(nlink instanceof Number) || ((Number) nlink).longValue() > 1) {
            if (nlink instanceof Number && ((Number) nlink).longValue() > 1) {
                throw new SigningflowException.InvalidRequestException("The file must not be a hard link.");
            }
            throw new SigningflowException.InvalidRequestException("The file could not be read.");
        }
        long size = Files.size(leaf);
        if (size > maxBytes) {
            throw new SigningflowException.InvalidRequestException("The file is larger than 25 MB.");
        }
        if (size == 0) {
            return new byte[0];
        }
        try (FileChannel channel = FileChannel.open(leaf, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            if (channel.size() != size) {
                throw new SigningflowException.InvalidRequestException("The file could not be read.");
            }
            ByteBuffer buffer = ByteBuffer.allocate((int) size);
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    throw new SigningflowException.InvalidRequestException("The file could not be read.");
                }
            }
            return buffer.array();
        }
    }
}
