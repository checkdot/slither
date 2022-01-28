import re
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.formatters.naming_convention.naming_convention import custom_format


class FeeMention(AbstractDetector):
    """
    Documentation
    """

    ARGUMENT = "fee-mention"
    HELP = "Fees in the contract detected"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#conformance-to-solidity-naming-conventions"

    WIKI_TITLE = "Fees in the contract detected"
    WIKI_DESCRIPTION = "Fees in the contract detected"
    WIKI_RECOMMENDATION = (
        "Remove the fees from your contract."
    )
    WIKI_EXPLOIT_SCENARIO = "Emit transaction"

    STANDARD_JSON = False

    @staticmethod
    def should_fee_name(name):
        return re.search("fees|fee|Fees|Fee", name) is not None

    def _detect(self):  # pylint: disable=too-many-branches,too-many-statements

        results = []
        fees_detected = False
        vars_names = ""
        for contract in self.contracts:
            for var in contract.state_variables_declared:
                if self.should_fee_name(var.name):
                    fees_detected = True
                    if vars_names != "":
                        vars_names += ", "
                    vars_names += var.name + " (" + var._get_lines_str() + ")"
        if fees_detected:
            info = [
                "Variable(s) ",
                vars_names,
                " Suspected fees in the Contract\n",
            ]
            res = self.generate_result(info)
            res.add(
                var,
                {
                    "target": "variable",
                    "convention": "fees_suspicion",
                },
            )
            results.append(res)

        return results
