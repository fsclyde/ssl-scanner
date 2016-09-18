from example_samplers import *

def run(app, xyzzy):
    samplers = [
        SynergySampler(xyzzy, 3),
        BuzzwordsSampler(xyzzy, 3), # 10
        WebsiteUpSampler(xyzzy, 3),
        LastScannedURL(xyzzy, 3)
    ]

    try:
        app.run(port=8081,
                threaded=True,
                use_reloader=False,
                host="0.0.0.0"
                )
    finally:
        print "Disconnecting clients"
        xyzzy.stopped = True
        
        print "Stopping %d timers" % len(samplers)
        for (i, sampler) in enumerate(samplers):
            sampler.stop()

    print "Done"
