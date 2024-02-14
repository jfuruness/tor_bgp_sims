from bgpy.simulation_engine import ROVSimplePolicy


class GuardValid24(ROVSimplePolicy):
    name = "Valid by ROA, /24"


class GuardValidNot24(ROVSimplePolicy):
    name = "Valid by ROA, shorter than /24"


class GuardNotValid24(ROVSimplePolicy):
    name = "Not valid by ROA, /24"


class GuardNotValidNot24(ROVSimplePolicy):
    name = "Not valid by ROA, shorter than /24"


class Dest24(ROVSimplePolicy):
    name = "/24"


class DestValidNot24(ROVSimplePolicy):
    name = "Valid by ROA, shorter than /24"


class DestNotValidNot24(ROVSimplePolicy):
    name = "Not valid by ROA, shorter than /24"
