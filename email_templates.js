const getResetEmailTemplate = (resetLink) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        .btn:hover { background-color: #6ba237 !important; }
      </style>
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f7;">
      <table role="presentation" style="width: 100%; border-collapse: collapse;">
        <tr>
          <td align="center" style="padding: 40px 0;">
            <table role="presentation" style="width: 600px; border-collapse: separate; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border: 2px solid #7bc142;">
              <tr>
                <td style="padding: 40px; text-align: center;">
                  
                  <h2 style="margin-top: 0; color: #333333; font-size: 24px; font-weight: 700;">Resetowanie hasła</h2>
                  
                  <p style="color: #666666; font-size: 16px; line-height: 1.6; margin-top: 20px;">
                    Otrzymaliśmy prośbę o zmianę hasła do Twojego konta. Jeśli to nie Ty, zignoruj tę wiadomość.
                  </p>
                  
                  <p style="color: #666666; font-size: 16px; line-height: 1.6;">
                    Aby ustawić nowe hasło, kliknij w przycisk poniżej:
                  </p>

                  <div style="text-align: center; margin: 35px 0;">
                    <a href="${resetLink}" class="btn" style="background-color: #7bc142; color: #ffffff; padding: 14px 32px; text-decoration: none; border-radius: 50px; font-weight: bold; font-size: 16px; display: inline-block; box-shadow: 0 4px 10px rgba(123, 193, 66, 0.3);">
                      Zresetuj moje hasło
                    </a>
                  </div>

                  <p style="color: #999999; font-size: 14px; margin-top: 30px; border-top: 1px solid #eeeeee; padding-top: 20px;">
                    Link jest ważny przez <strong>24 godziny</strong>.<br>
                    Jeśli przycisk nie działa, skopiuj poniższy link do przeglądarki:<br>
                    <a href="${resetLink}" style="color: #7bc142; word-break: break-all; text-decoration: none;">${resetLink}</a>
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
  `;
};

module.exports = { getResetEmailTemplate };
