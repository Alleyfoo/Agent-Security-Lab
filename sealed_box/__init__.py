"""The sealed box: §8 of the frozen design philosophy, made measurable.

    If the agent becomes completely persuaded by hostile input, can that
    persuasion create authority the surrounding system did not provide?

The agent's internal state is treated as permanently unobservable. No security
decision reads anything the agent authored, and the agent's state is enumerated
rather than sampled - including the maximally captured one - so a result that
holds for the worst state holds without knowing the real one.
"""
