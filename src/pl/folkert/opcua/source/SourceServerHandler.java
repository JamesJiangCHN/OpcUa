package pl.folkert.opcua.source;

import java.io.IOException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.channel.group.DefaultChannelGroup;

public class SourceServerHandler extends SimpleChannelUpstreamHandler {

    private static final ChannelGroup channelGroup = new DefaultChannelGroup();
    private static final Logger logger = Logger.getLogger(SourceServerHandler.class.getName());
    private final ChannelBuffer currentBuffer = ChannelBuffers.buffer(16);

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) {
	ChannelBuffer message = (ChannelBuffer) e.getMessage();
	int sourceMessage = message.readInt();
	if (SourceMessage.fromInt(sourceMessage).equals(SourceMessage.GET)) {
	    currentBuffer.clear();
	    currentBuffer.writeInt(SourceServer.currentValue);
	    currentBuffer.writeLong(new Date().getTime());
	    e.getChannel().write(currentBuffer);
	}
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) {
	if (e.getCause() instanceof IOException) {
	    e.getChannel().close();
	} else {
	    logger.log(Level.WARNING, "Unexpected exception from downstream.", e.getCause());
	}
    }

    @Override
    public void channelOpen(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
	super.channelOpen(ctx, e);
	channelGroup.add(e.getChannel());
	System.out.println("Channel " + e.getChannel() + " added.");
    }

    @Override
    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
	super.channelClosed(ctx, e);
	channelGroup.remove(e.getChannel());
	System.out.println("Channel " + e.getChannel() + " removed.");
    }
}
