# 新版需要更新 Firestore Rules

新版加入每月預算資料、每日熱量／蛋白質／喝水／睡眠目標設定（存在 `settings/goals`）、記帳自訂分類（存在 `settings/categories`），以及**每月資產盤點資料（存在新的 `assets/{月份}` 集合，這是這次新加的，請確認已加入下面的規則）**。請到 Firebase Console → Firestore Database → Rules，貼上並發布：

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/journal/{entryId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /users/{userId}/budget/{monthId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /users/{userId}/settings/{docId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /users/{userId}/assets/{monthId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

> 若還沒加這條規則，登入時會跳出「Missing or insufficient permissions」，程式碼已經改成失敗時會用預設值繼續運作、不會卡住今日資料，但目標／分類／資產盤點的讀寫還是會失敗，請盡快到 Firebase Console 更新。
