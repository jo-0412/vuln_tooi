# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import re

from app.compat import to_text


TEXT_REPLACEMENTS = [
    ("자동 판정이 어렵습니다.", "Automatic determination is difficult."),
    ("점검 실행 중 오류가 발생했습니다.", "An error occurred while running the check."),
    ("판정 근거:", "Decision reasons:"),
    ("조치 안내", "Remediation"),
    ("수집 증적", "Collected Evidence"),
    ("오류", "Errors"),
    ("요약", "Summary"),
    ("상세", "Detail"),
    ("상태:", "Status:"),
    ("중요도:", "Severity:"),
    ("분류:", "Category:"),
    ("root 권한 필요 여부:", "Requires root privileges:"),
    ("점검 시각:", "Checked at:"),
    ("설정 파일 누락, 비표준 PAM 구성, 배포판별 차이 등으로 인해 추가 확인이 필요합니다.",
     "Due to missing configuration files, non-standard PAM configuration, or distribution-specific differences, additional verification is required."),
    ("설정 파일 누락, 비표준 설치 경로, 버전별 기본값 차이 등으로 인해 추가 확인이 필요합니다.",
     "Due to missing configuration files, non-standard installation paths, or version-specific default differences, additional verification is required."),
    ("필수 파일을 읽지 못했거나 점검에 필요한 정보 수집 중 오류가 발생했습니다.",
     "A required file could not be read, or an error occurred while collecting information needed for the check."),
    ("파일을 읽지 못했습니다.", "file could not be read."),
    ("파일을 읽지 못해", "file could not be read, so"),
    ("파일을 찾지 못했습니다.", "file was not found."),
    ("파일이 존재하지 않습니다.", "File does not exist."),
    ("명령 없음", "command unavailable"),
    ("디렉터리 순회 오류:", "Directory traversal error:"),

    ("root 계정 원격 접속 제한", "Restrict Remote root Login"),
    ("root 계정의 원격 직접 접속이 차단되어 있습니다.", "Direct remote login for the root account is blocked."),
    ("원격 터미널 서비스를 사용하지 않거나, 사용 중인 서비스에서 root 직접 로그인이 제한되어 있어 양호합니다.",
     "Remote terminal services are not used, or direct root login is restricted in the services in use, so the configuration is compliant."),
    ("root 계정의 원격 직접 접속이 허용되어 있습니다.", "Direct remote login for the root account is allowed."),
    ("SSH/Telnet 원격 터미널 서비스가 활성 상태가 아닙니다.",
     "SSH/Telnet remote terminal services are not active."),
    ("SSH는 PermitRootLogin no 로 설정하고, Telnet 계열은 root 직접 접속을 차단해야 합니다.",
     "Set SSH to PermitRootLogin no and block direct root login for Telnet-family services."),

    ("비밀번호 관리정책 설정", "Configure Password Management Policy"),
    ("비밀번호 관리정책이 적절히 설정되어 있습니다.", "The password management policy is properly configured."),
    ("비밀번호 관리정책이 없거나 약하게 설정되어 있습니다.", "The password management policy is missing or weakly configured."),
    ("비밀번호 복잡도, 변경 주기, 재사용 금지 정책을 강화해야 합니다.",
     "Strengthen password complexity, change cycle, and reuse prevention policies."),
    ("/etc/security/pwquality.conf 에 최소 길이 8 이상을 설정합니다.",
     "Set the minimum length to 8 or more in /etc/security/pwquality.conf."),
    ("숫자, 대문자, 소문자, 특수문자 조합 정책을 설정합니다.",
     "Configure a policy requiring a combination of digits, uppercase letters, lowercase letters, and special characters."),
    ("가능하면 enforce_for_root 를 추가하여 root 계정에도 동일 정책을 적용합니다.",
     "If possible, add enforce_for_root so the same policy also applies to the root account."),
    ("/etc/login.defs 에 PASS_MIN_DAYS 1, PASS_MAX_DAYS 90 을 설정합니다.",
     "Set PASS_MIN_DAYS 1 and PASS_MAX_DAYS 90 in /etc/login.defs."),
    ("/etc/security/pwhistory.conf 또는 PAM 설정에서 최근 4회 이상 비밀번호 재사용 금지를 설정합니다.",
     "In /etc/security/pwhistory.conf or PAM settings, prohibit reuse of at least the last 4 passwords."),
    ("/etc/pam.d/common-password 에서 pam_pwquality.so 와 pam_pwhistory.so 가 pam_unix.so 보다 앞에 적용되도록 정렬합니다.",
     "In /etc/pam.d/common-password, order pam_pwquality.so and pam_pwhistory.so before pam_unix.so."),
    ("비밀번호 복잡도 정책 파일(pwquality.conf)을 읽지 못해 수동 확인이 필요합니다.",
     "The password complexity policy file (pwquality.conf) could not be read, so manual verification is required."),
    ("비밀번호 사용기간 정책 파일(login.defs)을 읽지 못해 수동 확인이 필요합니다.",
     "The password age policy file (login.defs) could not be read, so manual verification is required."),
    ("최근 비밀번호 재사용 금지 설정 파일을 읽지 못해 수동 확인이 필요합니다.",
     "The recent password reuse prevention configuration file could not be read, so manual verification is required."),
    ("최근 비밀번호 재사용 금지 설정 file could not be read, so 수동 확인이 필요합니다.",
     "The recent password reuse prevention configuration file could not be read, so manual verification is required."),
    ("PAM 정책 파일(common-password/system-auth)을 읽지 못해 수동 확인이 필요합니다.",
     "The PAM policy file (common-password/system-auth) could not be read, so manual verification is required."),
    ("pwquality.conf 파일을 읽지 못했습니다.", "The pwquality.conf file could not be read."),
    ("login.defs 파일을 읽지 못했습니다.", "The login.defs file could not be read."),
    ("PAM 정책 파일을 읽지 못했습니다.", "The PAM policy file could not be read."),
    ("PAM 정책 file could not be read.", "The PAM policy file could not be read."),

    ("계정 잠금 임계값 설정", "Configure Account Lockout Threshold"),
    ("계정 잠금 임계값이 적절히 설정되어 있습니다.", "The account lockout threshold is properly configured."),
    ("계정 잠금 임계값이 없거나 기준에 맞지 않습니다.", "The account lockout threshold is missing or does not meet the criteria."),
    ("PAM 관련 설정 파일 또는 faillock.conf 를 읽지 못해 수동 확인이 필요합니다.",
     "PAM-related configuration files or faillock.conf could not be read, so manual verification is required."),
    ("계정 잠금 임계값을 10회 이하로 설정하고 잠금 해제 및 PAM 적용 순서를 올바르게 구성해야 합니다.",
     "Set the account lockout threshold to 10 attempts or fewer, and correctly configure unlock handling and PAM order."),

    ("비밀번호 파일 보호", "Protect Password Files"),
    ("비밀번호 파일이 적절히 보호되고 있습니다.", "Password files are properly protected."),
    ("비밀번호 파일 보호 설정이 미흡합니다.", "Password file protection is insufficient."),
    ("/etc/passwd 파일을 읽지 못해 판정할 수 없습니다.",
     "/etc/passwd could not be read, so the check cannot determine the result."),
    ("/etc/passwd file could not be read, so 판정할 수 없습니다.",
     "/etc/passwd could not be read, so the check cannot determine the result."),
    ("쉐도우 비밀번호 사용 여부를 확인하고, 비밀번호가 passwd 파일에 직접 저장되지 않도록 조치해야 합니다.",
     "Verify shadow password usage and ensure passwords are not stored directly in the passwd file."),
    ("/etc/passwd 의 두 번째 필드가 x 로 설정되어 있는지 확인합니다.",
     "Verify that the second field in /etc/passwd is set to x."),
    ("/etc/shadow 파일이 존재하는지 확인합니다.", "Verify that /etc/shadow exists."),
    ("쉐도우 비밀번호를 사용하지 않는 경우 pwconv 등을 이용해 쉐도우 비밀번호를 적용합니다.",
     "If shadow passwords are not used, apply shadow passwords using pwconv or an equivalent tool."),
    ("/etc/passwd 에 직접 비밀번호 해시 또는 평문이 저장되어 있다면 즉시 제거하고 쉐도우 구조로 전환합니다.",
     "If password hashes or plaintext passwords are stored directly in /etc/passwd, remove them immediately and switch to a shadow structure."),
    ("HP-UX 계열은 필요 시 Trusted Mode 전환을 검토합니다.",
     "For HP-UX-family systems, consider switching to Trusted Mode if needed."),
    ("AIX 계열은 /etc/security/passwd 저장 구조를 확인합니다.",
     "For AIX-family systems, check the /etc/security/passwd storage structure."),
    ("적용 전 관련 계정 파일을 반드시 백업하고 root 권한으로 수행합니다.",
     "Before applying changes, back up related account files and perform the work with root privileges."),
    ("/etc/passwd 파일을 읽지 못했습니다.", "/etc/passwd could not be read."),
    ("/etc/passwd 존재 여부", "/etc/passwd existence status"),
    ("/etc/shadow 존재 여부", "/etc/shadow existence status"),
    ("/etc/shadow 읽기 가능 여부", "Whether /etc/shadow is readable"),
    ("AIX 비밀번호 저장 파일 존재 여부", "AIX password storage file existence status"),
    ("HP-UX Trusted Mode 경로 존재 여부", "HP-UX Trusted Mode path existence status"),
    ("pwconv 명령 사용 가능 여부", "Whether the pwconv command is available"),

    ("root 이외의 UID가 0 금지", "Prohibit UID 0 Accounts Other Than root"),
    ("root 외 UID 0 계정을 제거하거나 일반 UID로 변경해야 합니다.",
     "Remove UID 0 accounts other than root or change them to normal UIDs."),
    ("/etc/passwd 파일을 읽지 못해 UID 0 계정을 판정할 수 없습니다.",
     "/etc/passwd could not be read, so UID 0 accounts cannot be evaluated."),
    ("/etc/passwd file could not be read, so UID 0 계정을 판정할 수 없습니다.",
     "/etc/passwd could not be read, so UID 0 accounts cannot be evaluated."),
    ("UID가 0인 계정 목록을 확인합니다.", "Review the list of accounts with UID 0."),
    ("불필요한 계정은 삭제합니다.", "Delete unnecessary accounts."),
    ("업무상 필요한 계정이라면 usermod -u 명령으로 0이 아닌 중복되지 않은 UID로 변경합니다.",
     "If the account is required for business operations, use usermod -u to change it to a non-zero, non-duplicate UID."),
    ("변경 전 해당 계정의 서비스 영향도와 파일 소유권 영향을 검토합니다.",
     "Before changing it, review service impact and file ownership impact for the account."),
    ("조치 전 /etc/passwd 및 관련 계정 정보를 반드시 백업합니다.",
     "Before remediation, back up /etc/passwd and related account information."),

    ("/etc/shadow 파일 소유자 및 권한 설정", "Configure /etc/shadow Owner and Permissions"),
    ("Linux 표준 경로가 아니거나 플랫폼별 대체 저장 구조가 확인되어 추가 확인이 필요합니다.",
     "Additional verification is required because this is not a standard Linux path or a platform-specific alternative storage structure was detected."),
    ("Linux 표준 경로가 아니거나 플랫폼별 대체 저장 구조가 확인되어 additional verification is required.",
     "Additional verification is required because this is not a standard Linux path or a platform-specific alternative storage structure was detected."),
    ("/etc/shadow 파일을 찾지 못했습니다.", "/etc/shadow was not found."),
    ("/etc/shadow 파일은 root 소유, 0400 이하 권한으로 제한해야 합니다.",
     "The /etc/shadow file must be owned by root and restricted to permission 0400 or more restrictive."),
    ("/etc/shadow 파일 소유자를 root 로 설정합니다.", "Set the owner of /etc/shadow to root."),
    ("/etc/shadow 파일 권한을 0400 으로 제한합니다.", "Restrict /etc/shadow permissions to 0400."),
    ("필요 시 chown root /etc/shadow 명령으로 소유자를 수정합니다.",
     "If needed, change the owner using chown root /etc/shadow."),
    ("필요 시 chmod 400 /etc/shadow 명령으로 권한을 수정합니다.",
     "If needed, change permissions using chmod 400 /etc/shadow."),
    ("AIX 계열은 /etc/security/passwd 를 확인합니다.",
     "For AIX-family systems, check /etc/security/passwd."),
    ("HP-UX 계열은 /tcb/files/auth 경로의 보호 상태를 확인합니다.",
     "For HP-UX-family systems, check the protection status of /tcb/files/auth."),
    ("변경 전 관련 파일을 반드시 백업합니다.", "Back up related files before making changes."),

    ("SUID, SGID, Sticky bit 설정 파일 점검", "Check Files with SUID, SGID, and Sticky Bit Settings"),
    ("전체 파일시스템 검색 또는 특수권한 항목 수집 중 오류가 발생했습니다.",
     "An error occurred while scanning the full filesystem or collecting special-permission items."),
    ("불필요한 특수권한은 제거하고 필요한 경우 최소 권한만 부여해야 합니다.",
     "Remove unnecessary special permissions and grant only the minimum required permissions when needed."),

    ("접속 IP 및 포트 제한", "Restrict Access by IP and Port"),
    ("접근 통제 파일 또는 방화벽 정책 수집 중 오류가 발생했습니다.",
     "An error occurred while collecting access control files or firewall policies."),
    ("접근 통제 관련 파일과 명령 결과를 충분히 수집하지 못했습니다.",
     "Access-control-related files and command results could not be collected sufficiently."),
    ("허용된 IP와 포트만 열고 나머지는 차단하도록 접근 통제를 구성해야 합니다.",
     "Configure access control so only allowed IPs and ports are open and all others are blocked."),
    ("TCP Wrapper(hosts.allow, hosts.deny) 사용 시 허용 서비스와 허용 호스트만 명시합니다.",
     "When using TCP Wrapper(hosts.allow, hosts.deny), specify only allowed services and allowed hosts."),
    ("iptables, firewalld, UFW 중 운영 환경에 맞는 방화벽으로 허용 포트와 허용 IP만 열어둡니다.",
     "Using a firewall suited to the operating environment among iptables, firewalld, or UFW, open only allowed ports and allowed IPs."),
    ("SSH 서비스는 가능하면 특정 관리망 또는 관리 IP에서만 접근하도록 제한합니다.",
     "Restrict SSH service access to specific management networks or management IPs whenever possible."),
    ("불필요하게 외부에 열려 있는 포트는 차단합니다.",
     "Block ports unnecessarily exposed to external networks."),
    ("변경 전 현재 방화벽 정책과 네트워크 서비스 영향을 반드시 검토합니다.",
     "Before changes, review current firewall policies and network service impact."),

    ("주기적 보안 패치 및 벤더 권고사항 적용", "Apply Periodic Security Patches and Vendor Advisories"),
    ("패치 관리 상태를 추가 확인해야 합니다.", "Patch management status requires additional verification."),
    ("정책에 따른 시스템 로깅 설정", "Configure System Logging According to Policy"),
    ("시스템 로깅 정책 준수 여부를 추가 확인해야 합니다.",
     "System logging policy compliance requires additional verification."),
]


def translate_text(text):
    value = to_text(text)
    for source, target in TEXT_REPLACEMENTS:
        value = value.replace(source, target)
    return value


def translate_object(value):
    if isinstance(value, dict):
        return {translate_text(k): translate_object(v) for k, v in value.items()}
    if isinstance(value, list):
        return [translate_object(item) for item in value]
    if isinstance(value, tuple):
        return tuple(translate_object(item) for item in value)
    if isinstance(value, str):
        return translate_text(value)
    return value


def has_korean(text):
    return re.search(r"[\uac00-\ud7a3]", to_text(text)) is not None
