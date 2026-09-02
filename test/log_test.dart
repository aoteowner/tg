import 'package:nop/utils.dart';
import 'package:test/test.dart';
import 'package:tg_api/api.dart';
import 'package:tg_api/users.dart';

void main() {
  test("log test", () {
    final user = UserFullHash3b6d152e(
      fullUser: UserFullHash06cbe645(
        id: 13131,
        settings: PeerSettingsHashf47741f7(),
        notifySettings: PeerNotifySettingsHash99622c0c(
          iosSound: NotificationSoundDefaultHash97e8bebe(),
        ),
        commonChatsCount: 1,
      ),
      chats: [],
      users: [],
    );
    Log.w(user.toJson().logPretty());
  });
}
