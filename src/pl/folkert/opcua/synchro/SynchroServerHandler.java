package pl.folkert.opcua.synchro;

import java.io.IOException;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.channel.group.DefaultChannelGroup;
import pl.folkert.opcua.Common;

public class SynchroServerHandler extends SimpleChannelUpstreamHandler {

    private final ScheduledExecutorService scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
    private static final int INITIAL_DELAY = 0;
    private static final ChannelGroup channelGroup = new DefaultChannelGroup();
    private Channel primary;
    private Channel secondary;
    private static final Logger logger = Logger.getLogger(SynchroServerHandler.class.getName());

    public SynchroServerHandler() {
	scheduledExecutor.scheduleAtFixedRate(new Runnable() {

	    ChannelBuffer buffer = ChannelBuffers.buffer(12);

	    @Override
	    public void run() {
		buffer.clear();
		buffer.writeInt(SynchroMessage.SYNCHRO.ordinal());
		buffer.writeLong(new Date().getTime());
		channelGroup.write(buffer);
	    }
	}, INITIAL_DELAY, Common.SYNCHRO_INTERVAL, TimeUnit.MILLISECONDS);
    }

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) {
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
	if (channelGroup.isEmpty()) {
	    primary = e.getChannel();
	} else if (channelGroup.size() == 1) {
	    secondary = e.getChannel();
	}
	channelGroup.add(e.getChannel());
	System.out.println("Channel " + e.getChannel() + " added.");
    }

    @Override
    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
	super.channelClosed(ctx, e);
	if (e.getChannel().equals(primary)) {
	    ChannelBuffer switchBuffer = ChannelBuffers.buffer(12);
	    switchBuffer.writeInt(SynchroMessage.PRIMARY.ordinal());
	    switchBuffer.writeLong(new Date().getTime());
	    if (secondary != null) {
		secondary.write(switchBuffer);
	    }
	}
	channelGroup.remove(e.getChannel());
	System.out.println("Channel " + e.getChannel() + " removed.");
    }
}
