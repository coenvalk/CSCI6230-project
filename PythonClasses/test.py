#!/usr/bin/env python3

import Number_Package as npkg
import numpy as np
import time


p, q, n = npkg.blum_interger_generator(p_q_min=100, p_ignore=2, q_ignore=30)
print(p, q, n)
