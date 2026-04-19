"""
hCaptcha HSJ solver package.

Public API:
    HCaptchaSolver     — solver class
    solve_hcaptcha     — convenience function
    set_solver_debug   — toggle debug logs
"""
from .hcaptcha_solver import HCaptchaSolver, solve_hcaptcha, set_solver_debug

__all__ = ["HCaptchaSolver", "solve_hcaptcha", "set_solver_debug"]
