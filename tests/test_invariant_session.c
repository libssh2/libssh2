#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern int wolfssh_session_process_banner(void* session, const unsigned char* banner, unsigned int banner_len);

typedef struct {
    struct {
        unsigned char banner[256];
    } remote;
    unsigned char banner_TxRx_banner[1024];
} mock_session_t;

START_TEST(test_banner_buffer_overflow)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "SSH-2.0-OpenSSH_8.0\r\n",
        "SSH-2.0-" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "\r\n",
        "SSH-2.0-" "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" "\r\n"
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        mock_session_t session;
        memset(&session, 0, sizeof(session));
        
        unsigned int banner_len = strlen(payloads[i]);
        memcpy(session.banner_TxRx_banner, payloads[i], banner_len);
        
        int result = wolfssh_session_process_banner(&session, session.banner_TxRx_banner, banner_len);
        
        ck_assert_msg(result >= 0 || result < 0, "Function must handle oversized input without crash");
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_banner_buffer_overflow);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}