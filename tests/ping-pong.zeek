@load frameworks/cluster/websocket/server

module test::zeekpy;

export {
	global ping: event(c: count);
	global pong: event(c: count);

	global set_ping: event(s: set[count, int, string]);
	global set_pong: event(s: set[count, int, string]);

	global tbl_ping: event(t: table[count, int, string] of count);
	global tbl_pong: event(t: table[count, int, string] of count);

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

event set_ping(s: set[count, int, string])
	{
	Cluster::publish(ping_topic, test::zeekpy::set_pong, s);
	}

event tbl_ping(s: table[count, int, string] of count)
	{
	Cluster::publish(ping_topic, test::zeekpy::tbl_pong, s);
	}

event tick(c: count)
	{
	Cluster::publish(ping_topic, test::zeekpy::ping, c);
	schedule 0.001msec { tick(++c) };
	}

event zeek_init()
	{
	if ( getenv("TEST_PRODUCE_PINGS") != "" )
		schedule 0.1msec { tick(1) };
	}
