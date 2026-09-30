#　概要
    このプロジェクトは、SFLLを適用したSIMECK32/64暗号システムに対し、DFAでマスター鍵を復元するシミュレーターである。


#内容物
1. no_ll_main with_ll_main with_sfll_main
    この3つプログラムは、LL適用なし・XOR型LL適用あり・SFLL適用ありのmainプログラムである。
    XOR型LLの場合、すべての32ラウンドにLLを適用する。
    SFLLの場合、すべての32ラウンドに内部状態とSecret Patternのハミング距離がちょうど8と等しくならLLを適用する。

    流れ：
    STEP 1 初期化
    STEP 2 SFLL適用・故障注入なしの暗号文を取得
    STEP 3~6 DFA K31~K28(ラウンド31~28)を復元
    STEP 7~8 復元した4つラウンドを出力および検証

2. encryption.c / .h
    平文を入力し、暗号文を出力するプログラムである。
    故障注入あり・なし、およびSFLL適用あり・SFLL適用なしの関数がある。

    関数の説明：
    true_encryption / true_ll_encryption / true_sfll_encryption
    STEP 2 に使われる関数
    攻撃者は故障なしの暗号文を取得する
    fault_encryption / fault_ll_encryption / fault_sfll_encryption
    STEP 3~6 に使われる関数
    攻撃者は特定のラウンドに故障注入で故障なしの暗号文を取得する

3. dfa.c / .h
    攻撃者はラウンド(T-1)に故障を注入し、KT(ラウンドTの鍵)を復元する。
    Improved Fault Analysis on SIMECK Ciphers
    Duc-Phong Le, Rongxing Lu, Senior Member, IEEE, and Ali A. Ghorbani, Senior Member, IEEE
    論文に掲載されている方法でラウンド鍵ビットを復元する。

    関数の説明：
    dfa_k31 ... dfa_k28
    LLなしおよびXOR型LLに対するDFA
    dfa_with_sfll_k31 ... dfa_with_sfll_k28
    SFLLに対するDFA

4. decryption.c / .h
   攻撃者は4つラウンド鍵を取得した後、それらの鍵をkey scheduleでマスター鍵を逆算し、真の鍵であるかを検証する。

   関数の説明：
   recover_master_key
   K28~K31を入力し、マスター鍵(K0~K3)を算出する

5. test_main
    テスト用のプログラムである。


#今後の開発予定
    攻撃者がSFLL keyと得られた暗号文を用いて、差分を復元する
        （SFLL適用の場合、一部の差分は差分伝搬に従わないため、故障注入位置および鍵ビットを取得できない）
        今までの攻撃が得られた差分の一部は（真の差分 XOR SFLL_key）と等しいため、SFLL keyで真の差分を復元できる
        しかし、真の差分を取得できなかった場合、鍵ビットを復元できなくなる

#プログラムの実行
    gcc with_sfll_main.c encryption.c dfa.c decryption.c -o main
    ./main
    
    