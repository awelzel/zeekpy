@load frameworks/cluster/websocket/server

module test::zeekpy;

export {
	global ping: event(c: count);
	global pong: event(c: count);

	const ping_topic = "zeekpy.test.ping";
}

event zeek_init()
	{
	Cluster::subscribe(ping_topic);
	}

event ping(c: count)
	{
	Cluster::publish(ping_topic, test::zeekpy::pong, c);
	}
