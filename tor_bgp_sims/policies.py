from bgpy.simulation_engine import ROVPolicy


class GuardValid24(ROVPolicy):
    name = "Valid by ROA, /24"


class GuardValidNot24(ROVPolicy):
    name = "Valid by ROA, shorter than /24"


class GuardNotValid24(ROVPolicy):
    name = "Not valid by ROA, /24"


class GuardNotValidNot24(ROVPolicy):
    name = "Not valid by ROA, shorter than /24"


class Dest24(ROVPolicy):
    name = "/24"


class DestValidNot24(ROVPolicy):
    name = "Valid by ROA, shorter than /24"


class DestNotValidNot24(ROVPolicy):
    name = "Not valid by ROA, shorter than /24"
