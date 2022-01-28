"""
    Module detecting send to arbitrary address

    To avoid FP, it does not report:
        - If msg.sender is used as index (withdraw situation)
        - If the function is protected
        - If the value sent is msg.value (repay situation)
        - If there is a call to transferFrom

    TODO: dont report if the value is tainted by msg.value
"""
from typing import List

from slither.core.cfg.node import Node
from slither.core.declarations import Function, Contract
from slither.analyses.data_dependency.data_dependency import is_tainted, is_dependent
from slither.core.declarations.solidity_variables import (
    SolidityFunction,
    SolidityVariableComposed,
)
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import (
    HighLevelCall,
    Index,
    LowLevelCall,
    Send,
    SolidityCall,
    Transfer,
    Operation
)


# pylint: disable=too-many-nested-blocks,too-many-branches
from slither.utils.output import Output


def arbitrary_send(func: Function):
    if func.visibility in ["internal", "virtual"]:
        return []
    if func.name in ["constructor"]:
        return []
    arr = []
    for modifier in func.modifiers:
        arr.append(modifier.name)
    if 'onlyOwner' in arr: #common modifier
        return []

    ret: List[Node] = []
    for node in func.nodes:
        for ir in node.irs:

            if isinstance(ir, (Operation)) and ir.function.full_name == "_mint(address,uint256)":
                # print(ir.function.full_name, node.function)
                # if isinstance(ir.function, Function):
                print(ir.function.full_name, func.visibility, func.name, func.modifiers[0])
                if ir.function.full_name != "_mint(address,uint256)":
                    return False
                ret.append(node)

    return ret


def detect_arbitrary_send(contract: Contract):
    """
        Detect arbitrary send
    Args:
        contract (Contract)
    Returns:
        list((Function), (list (Node)))
    """
    ret = []
    for f in [f for f in contract.functions if f.contract_declarer == contract]:
        nodes = arbitrary_send(f)
        if nodes:
            ret.append((f, nodes))
    return ret


class MintDangerousToken(AbstractDetector):
    ARGUMENT = "mint-dangerous-token"
    HELP = "Unprotected function use mint erc20 function without modifier"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#mint-modifier"

    WIKI_TITLE = "Unprotected function use mint erc20 function without modifier"
    WIKI_DESCRIPTION = "Unprotected call to a function mint token without modifier"

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract UnprotectedMint{
    function mint(uint256 amount) public{
        _mint(msg.sender, amount);
    }
}
```
Bob calls `mint`. As a result he mint amount token to him wallet."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Add a modifier of right 'onlyOwner'."

    def _detect(self) -> List[Output]:
        """"""
        results = []

        for c in self.contracts:
            arbitrary_send_result = detect_arbitrary_send(c)
            for (func, nodes) in arbitrary_send_result:

                info = [func, " mint new tokens\n"]
                info += ["\tDangerous calls:\n"]

                # sort the nodes to get deterministic results
                nodes.sort(key=lambda x: x.node_id)

                for node in nodes:
                    info += ["\t- ", node, "\n"]

                res = self.generate_result(info)

                results.append(res)

        return results
