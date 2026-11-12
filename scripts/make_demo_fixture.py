"""Create a synthetic ZIP fixture, not an installable or real third-party APK."""
import sys
import zipfile
from pathlib import Path

target = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/demo.apk")
target.parent.mkdir(parents=True, exist_ok=True)
if target.exists():
    raise SystemExit("Refusing to overwrite an existing file.")
manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="org.example.apkgod.demo" android:versionCode="1" android:versionName="0.1-demo">
<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
<uses-permission android:name="android.permission.INTERNET"/>
<application android:label="APK GOD synthetic demo">
<activity android:name=".MainActivity" android:exported="true"/>
</application></manifest>"""
with zipfile.ZipFile(target, "w") as apk:
    apk.writestr("AndroidManifest.xml", manifest)
    apk.writestr("assets/demo.json", '{"notice":"Synthetic fixture, not an installable app","api":"https://example.invalid/api/items"}')
print("Synthetic fixture created:", target)
