from bgpy.simulation_framework import ASGraphAnalyzer


class CombinedASGraphAnalyzer(ASGraphAnalyzer):
    """Performs traceback for guard and dest attacker

    For an attacker to have the easiest time deanonomizing users
    they need to hijack both the connection going from the guard
    to the client, and also the connection going from the exit to
    the destination.

    This requires the attacker to use two non-overlapping prefixes
    and thus requires a custom traceback/ASGraphAnalyzer class

    Quite simply, this traceback performs only data plane traceback,
    and just does the traceback to get outcomes for attacker success
    against the guard, and then again to get attacker success against
    the exit, and then simply does an intersection of the two.

    It's important to note that for the exit-to-dest tracking, we only
    trace back to a single AS - the exit relay. So essentially, we perform
    __normal__ traceback for client-to-guard attack, and then if dest-to-exit
    is intercepted by the attacker, return the client-to-guard results, else
    all are victim success and not attacker success.

    It's also important to note that this form of traceback
    is __required__ for these metrics to work properly for this attack, but
    this form of traceback is __not__ enforced programmatically, so we don't
    recommend using this in other simulations, since we've just hardcoded this
    in as a one-off
    """

    pass
