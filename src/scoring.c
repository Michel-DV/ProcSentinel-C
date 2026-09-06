#include "procsentinel/procsentinel.h"

int ps_score_file(const PsFileReport *report) {
    int score = 0;
    if (!report) return 0;

    switch (report->signature) {
        case PS_SIGNATURE_UNSIGNED: score += 10; break;
        case PS_SIGNATURE_INVALID: score += 20; break;
        case PS_SIGNATURE_UNKNOWN: score += 5; break;
        case PS_SIGNATURE_TRUSTED: default: break;
    }

    if (report->pe.valid) {
        if (report->pe.has_wx_section) score += 35;
        if (report->pe.high_entropy_executable_section) score += 20;
        if (report->pe.entrypoint_in_writable_section) score += 25;
    }

    if (score > 100) score = 100;
    return score;
}
