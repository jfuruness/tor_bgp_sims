from bgpy.simulation_engine import ROV


class GuardValid24(ROV):
    name = "Valid by ROA, /24"


class GuardValidNot24(ROV):
    name = "Valid by ROA, shorter than /24"


class GuardNotValid24(ROV):
    name = "Not valid by ROA, /24"


class GuardNotValidNot24(ROV):
    name = "Not valid by ROA, shorter than /24"


class Dest24(ROV):
    name = "/24"


class DestValidNot24(ROV):
    name = "Valid by ROA, shorter than /24"


class DestNotValidNot24(ROV):
    name = "Not valid by ROA, shorter than /24"
