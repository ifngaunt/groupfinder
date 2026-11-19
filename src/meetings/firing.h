#pragma once
// What the scheduler should do for one meeting occurrence at a given moment. Pure logic
// (tests/test_firing.cpp); MeetingController applies the result.
#include <QDateTime>

#include "meetings/meeting.h"

namespace gf {

struct Occurrence {
    QDateTime startUtc;
    bool      warned    = false;  // warning pop-up already shown
    bool      cancelled = false;  // user clicked "Don't move me"
    bool      done      = false;  // already executed early ("Move now" / "Join now")
};

enum class FireAction {
    None,         // nothing to do yet
    ShowWarning,  // open the countdown pop-up
    Execute,      // move / connect now, then advance
    Advance,      // occurrence is over (done, cancelled or missed): compute the next one
};

constexpr qint64 kMissedGraceSecs = 300;  // execute up to 5 min late (e.g. PC woke from sleep)

FireAction decide(const Meeting& m, const Occurrence& occ, const QDateTime& nowUtc);

} // namespace gf
