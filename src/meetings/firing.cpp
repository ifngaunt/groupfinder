#include "meetings/firing.h"

namespace gf {

FireAction decide(const Meeting& m, const Occurrence& occ, const QDateTime& nowUtc)
{
    if (!m.enabled || !occ.startUtc.isValid())
        return FireAction::None;

    if (nowUtc >= occ.startUtc) {
        if (occ.cancelled || occ.done)
            return FireAction::Advance;
        if (occ.startUtc.secsTo(nowUtc) > kMissedGraceSecs)
            return FireAction::Advance;
        return FireAction::Execute;
    }

    if (m.action == Action::WarnThenMove && !occ.warned && !occ.cancelled && !occ.done &&
        nowUtc >= occ.startUtc.addSecs(-qint64(m.warnMinutes) * 60))
        return FireAction::ShowWarning;
    return FireAction::None;
}

} // namespace gf
