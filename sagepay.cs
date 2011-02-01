/*
 *  C# SagePay Reporting & Admin API wrapper
 *  
 *  Copyright (C) 2011. Colin Mackie
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Web;

namespace DBS
{
	/// <summary>
	/// Class wrapping the Report & Admin API from SagePay
	/// </summary>
	public class SagePay
	{
		/// <summary>
		/// Types of cards
		/// </summary>
		public enum CardType
		{
			NONE,
			AMEX,
			DC,
			DELTA,
			JCB,
			MAESTRO,
			MC,
			PAYPAL,
			SOLO,
			SWITCH,
			UKE,
			VISA,
			UNKNOWN
		}

		/// <summary>
		/// Types of accounts
		/// </summary>
		public enum AccountType
		{
			Ecommerce,
			Continuous,
			MOTO
		}

		/// <summary>
		/// CV and address results
		/// </summary>
		public enum CheckResult
		{
			MATCHED,
			NOTCHECKED,
			NOTPROVIDED,
			NOTMATCHED,
			PARTIAL
		}

		/// <summary>
		/// Secure3D results
		/// </summary>
		public enum Secure3DResult
		{
			OK,
			NOTCHECKED,
			ATTEMPTONLY,
			NOTAVAILABLE,
			NOTAUTHED,
			INCOMPLETE,
			ERROR
		}

		/// <summary>
		/// TxState return from GetTransactionDetails (see https://www.sagepay.com/help/faq/different_txstates)
		/// </summary>
		public enum TxState : int
		{
			None = 0,
			FailedRegistration = 1,							// Transaction failed registration.  Either an INVALID or MALFORMED response was returned.
			UserOnCardSelectionPage = 2,				// User on Card Selection page.
			UserOnCardDetailsPage = 3,					// User on the Card Details Entry Page.
			UserOnConfirmaionPage = 4,					// User on Confirmation Page.
			Secure3DAuthenticating = 5,					// Transaction at 3D-Secure Authentication Stage.
			SentForAuthorisation = 6,						// Transaction sent for Authorisation
			NotificationUrl = 7,								// Vendor Notified of transaction state at their NotificationURL.  Awaiting response.
			CancelledDueToInactivity = 8,				// Transaction CANCELLED by Sage Pay after 15 minutes of inactivity.  This is normally because the customer closed their browser.
			CompletedWithInvalidOrError = 9,		// Transaction completed but Vendor systems returned INVALID or ERROR in response to notification POST. Transaction CANCELLED by the Vendor.
			RejectedByRules = 10,								// Transaction REJECTED by the Fraud Rules you have in place.
			Aborted = 11,												// Transaction ABORTED by the Customer on the Payment Pages.
			Decline = 12,												// Transaction DECLINED by the bank (NOTAUTHED).
			CancelledUnknownError = 13,					// An ERROR occurred at Sage Pay which cancelled this transaction.
			Deferred = 14,											// Successful DEFERRED transaction, awaiting RELEASE.
			Authenticated = 15,									// Successful AUTHENTICATED transaction, awaiting AUTHORISE.
			Authorised = 16,										// Successfully authorised transaction.
			TimedOutDuringAuthorisation = 17,		// Transaction Timed Out at Authorisation Stage.
			Voided = 18,												// Transaction VOIDed by the Vendor.
			AbortDeferred = 19,									// Successful DEFERRED transaction ABORTED by the Vendor.
			TimedOut = 20,											// Transaction has been timed out by Sage Pay.
			Registered = 21,										// Successfully REGISTERED transaction, awaiting AUTHORISE.
			Cancelled = 22,											// AUTHENTICATED or REGISTERED transaction CANCELLED by the Vendor.
			SettlementFailed = 23,							// Transaction could not be settled with the bank and has been failed by the Sage Pay systems
			PayPalRegistered = 24,							// PayPal Transaction Registered
			TokenRegistered = 25,								// Token Registered
			AuthoriseExpiredOrFull = 26,				// AUTHENTICATE transaction that can no longer be AUTHORISED against.  It has either expired, or been fully authorised.
			Expired = 27												// DEFERRED transaction that expired before it was RELEASEd or ABORTed.
		}

		/// <summary>
		/// Live URL
		/// </summary>
		protected const string LIVE_URL = "https://live.sagepay.com/access/access.htm";

		/// <summary>
		/// Command names
		/// </summary>
		private static string COMMAND_GETCARDTYPE = "getCardType";
		private static string COMMAND_GETCARDDETAILS = "getCardDetails";
		private static string COMMAND_GETTRANSACTIONDETAIL = "getTransactionDetail";

		/// <summary>
		/// Mx number of digits to pass in when querying card
		/// </summary>
		private const int GETCARDTYPE_MAX_DIGITS = 9;

		/// <summary>
		/// Create a new SagePay admin object
		/// </summary>
		/// <param name="vendor">vendor name</param>
		/// <param name="user">admin user</param>
		/// <param name="password">admin user's password</param>
		/// <param name="test">flag for test system</param>
		public SagePay(string vendor, string user, string password, string adminUrl = LIVE_URL)
		{
			Vendor = vendor;
			User = user;
			Password = password;

			Url = (string.IsNullOrEmpty(adminUrl) == false ? adminUrl : LIVE_URL);
		}

		/// <summary>
		/// Get/set the URl to use
		/// </summary>
		protected string Url { get; set; }

		/// <summary>
		/// Get/set the Vendor
		/// </summary>
		public string Vendor { get; set; }

		/// <summary>
		/// Get/set the username
		/// </summary>
		public string User { get; set; }

		/// <summary>
		/// get/set the user's password
		/// </summary>
		public string Password { get; set; }

		#region Internal methods

		/// <summary>
		/// Build an xml command string with either the password or signature ready to sign
		/// </summary>
		/// <param name="command">API command</param>
		/// <param name="vendor">name of vendor</param>
		/// <param name="user">username</param>
		/// <param name="xmldata">optional extra data for api</param>
		/// <param name="password">optional password</param>
		/// <param name="signature">optional md5 signatture</param>
		/// <returns>inner xml node string</returns>
		private string BuildCommandString(string command, string vendor, string user, string xmldata, string password = null, string signature = null)
		{
			return string.Format("<command>{0}</command><vendor>{1}</vendor><user>{2}</user>{3}{4}{5}",
				command,
				Vendor,
				User,
				xmldata ?? string.Empty,
				(string.IsNullOrEmpty(password) == false ? "<password>" + password + "</password>" : string.Empty),
				(string.IsNullOrEmpty(signature) == false ? "<signature>" + signature + "</signature>" : string.Empty));
		}

		/// <summary>
		/// Perform the main call for the API and collect the response
		/// </summary>
		/// <param name="command">api command name</param>
		/// <param name="xmldata">optional extra data for api</param>
		/// <returns>new SagePayResponse or null if communication error</returns>
		protected SagePayResponse ProcessAPI(string command, string xmldata)
		{
			// get the requiest
			HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(Url);
			httpRequest.Method = "POST";

			// build data
			string data = BuildCommandString(command, Vendor, User, xmldata, Password);
			// apply signature
			MD5 md5 = new MD5CryptoServiceProvider();
			byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(data));
			string sig = BitConverter.ToString(hash).Replace("-", string.Empty);
			// rebuild with signature
			data = "XML=<vspaccess>" + BuildCommandString(command, Vendor, User, xmldata, null, sig) + "</vspaccess>";

			// get the data
			byte[] bytes = Encoding.UTF8.GetBytes(data);
			httpRequest.ContentType = "application/x-www-form-urlencoded";
			httpRequest.ContentLength = data.Length;

			// get the request stream
			Stream requestStream = httpRequest.GetRequestStream();
			requestStream.Write(bytes, 0, bytes.Length);
			requestStream.Close();

			// call the sagepay url and get response
			SagePayResponse sagePayResponse = null;
			HttpWebResponse response = (HttpWebResponse)httpRequest.GetResponse();
			try
			{
				if (response.StatusCode == HttpStatusCode.OK)
				{
					Stream responseStream = response.GetResponseStream();
					//string contentType = response.ContentType;
					StreamReader reader = new StreamReader(responseStream, Encoding.UTF8);
					try
					{
						sagePayResponse = new SagePayResponse(reader.ReadToEnd());
					}
					finally
					{
						reader.Close();
					}
				}
			}
			finally
			{
				response.Close();
			}

			return sagePayResponse;
		}

		#endregion

		#region APIs

		/// <summary>
		/// Get the card type depending on the first 1-9 digits
		/// </summary>
		/// <param name="cardNumber">card number</param>
		/// <returns>CardType of card</returns>
		public CardType GetCardType(string cardNumber)
		{
			// strip non-digts and only pass up to 9 digits
			string strippedNumber = Regex.Replace(cardNumber, @"[^\d]", string.Empty, RegexOptions.IgnoreCase);
			if (strippedNumber.Length > GETCARDTYPE_MAX_DIGITS)
			{
				strippedNumber = strippedNumber.Substring(0, GETCARDTYPE_MAX_DIGITS);
			}

			// call API and check for error
			SagePayResponse response = ProcessAPI(COMMAND_GETCARDTYPE, "<cardbegins>" + strippedNumber + "</cardbegins>");
			if (response.ErrorCode != 0)
			{
				throw new SagePageErrorException(response.ErrorCode, response.ErrorText);
			}

			// parse the retuend cardname string
			CardType cardType = Converter.ToCardType(response["paymentsystem"], CardType.NONE);
			if (cardType == CardType.NONE)
			{
				throw new SagePageUnknownCardException(response["paymentsystem"] ?? "[null]");
			}

			return cardType;
		}

		/// <summary>
		/// Get detailed card information based on the number
		/// </summary>
		/// <param name="cardNumber">card number</param>
		/// <returns>new SagePayCardDetails with card info</returns>
		public SagePayCardDetails GetCardDetails(string cardNumber)
		{
			// only pass up to 9 digits
			string strippedNumber = Regex.Replace(cardNumber, @"[^\d]", string.Empty, RegexOptions.IgnoreCase);
			if (strippedNumber.Length > GETCARDTYPE_MAX_DIGITS)
			{
				strippedNumber = strippedNumber.Substring(0, GETCARDTYPE_MAX_DIGITS);
			}

			// call APi and check for error
			SagePayResponse response = ProcessAPI(COMMAND_GETCARDDETAILS, "<cardbegins>" + strippedNumber + "</cardbegins>");
			if (response.ErrorCode != 0)
			{
				throw new SagePageErrorException(response.ErrorCode, response.ErrorText);
			}

			// build card info object
			SagePayCardDetails spcd = new SagePayCardDetails();
			spcd.CardType = Converter.ToCardType(response["shortname"]);
			spcd.Description = response["paymentsystemname"];
			spcd.IssueDigits = Converter.ToInt(response["issuedigits"]);
			//
			spcd.MinBinRange = Converter.ToDecimal(response["minimum"]);
			spcd.MaxBinRange = Converter.ToDecimal(response["maximum"]);
			//
			spcd.CountryCode = response["countrycode"];
			spcd.Issuer = response["issuer"];
			spcd.IsCorporate = (string.Compare(response["corporatecard"], "yes", true) == 0);
			spcd.IsCredit = (string.Compare(response["iscredit"], "yes", true) == 0);

			return spcd;
		}

		/// <summary>
		/// Get transaction information from the vendor's txid
		/// </summary>
		/// <param name="vendorTxId">txid for transaction</param>
		/// <returns>new SagePayTransactionDetails with details</returns>
		public SagePayTransactionDetails GetTransactionDetails(string vendorTxId)
		{
			// call the API and check for error
			SagePayResponse response = ProcessAPI(COMMAND_GETTRANSACTIONDETAIL, "<vendortxcode>" + vendorTxId + "</vendortxcode>");
			if (response.ErrorCode != 0)
			{
				throw new SagePageErrorException(response.ErrorCode, response.ErrorText);
			}

			// build an info object and fill from response
			SagePayTransactionDetails td = new SagePayTransactionDetails();
			td.TxID = response["vpstxid"];
			td.VendorTxCode = response["vendortxcode"];
			td.TxType = response["transactiontype"];
			td.TxStateId = Converter.ToTxState(response["txstateid"]);
			td.Status = response["status"];
			//
			td.RelatedTxId = response["relatedtransactionid"];
			td.RelatedVendorTxCode = response["relatedvendortxcode"];
			td.RelatedAmount = Converter.ToDecimal(response["relatedamount"]);
			td.RelatedCurrency= response["relatedcurrency"];
			td.RelatedStarted = Converter.ToDateTime(response["relatedstarted"], DateTime.MinValue);
			//
			td.Description = response["description"];
			td.Amount = Converter.ToDecimal(response["amount"]);
			td.Currency = response["currency"];
			td.Started = Converter.ToDateTime(response["started"], DateTime.MinValue);
			td.Completed = Converter.ToDateTime(response["completed"], DateTime.MinValue);
			//
			td.SecurityKey = response["securitykey"];
			td.ClientIP = response["clientip"];
			td.GiftAid = response["giftaid"];
			td.PaymentSystem = response["paymentsystem"];
			td.PaymentSystemDetails = response["paymentsystemdetails"];
			td.StartDate = response["startdate"];
			td.ExpiryDate = response["expirydate"];
			td.Last4Digits = response["last4digits"];
			td.AuthProcessor = response["authprocessor"];
			td.MerchantNumber = response["merchantnumber"];
			td.AccountType = Converter.ToAccountType(response["accounttype"]);
			td.AuthCode = Converter.ToLong(response["vpsauthcode"]);
			td.BankAuthCode = response["bankauthcode"];
			td.BatchId = Converter.ToInt(response["batchid"]);
			//
			td.CV2Result = Converter.ToCheckResult(response["cv2result"]);
			td.AddressResult = Converter.ToCheckResult(response["addressresult"]);
			td.PostcodeResult = Converter.ToCheckResult(response["postcoderesult"]);
			//
			td.Secure3DAttempts = Converter.ToInt(response["threedattempt"]);
			td.Secure3DResult = Converter.ToSecure3DResult(response["threedresult"]);
			td.T3MScore = Converter.ToInt(response["t3mscore"]);
			td.T3MAction = response["t3maction"];

			return td;
		}

		#endregion

		/// <summary>
		/// Internal converter class that can handle enums and defaults
		/// </summary>
		protected class Converter
		{
			public static int ToInt (string s, int d = 0)
			{
				int t;
				return (int.TryParse(s, out t) ? t : d);
			}
			public static long ToLong(string s, long d = 0)
			{
				long t;
				return (long.TryParse(s, out t) ? t : d);
			}
			public static decimal ToDecimal(string s, decimal d = 0)
			{
				decimal t;
				return (decimal.TryParse(s, out t) ? t : d);
			}
			public static DateTime ToDateTime(string s, DateTime d)
			{
				DateTime t;
				return (DateTime.TryParse(s, out t) ? t : d);
			}
			public static SagePay.CardType ToCardType(string s, SagePay.CardType d = CardType.NONE)
			{
				SagePay.CardType t;
				return (Enum.TryParse<SagePay.CardType>(s, true, out t) ? t : d);
			}
			public static SagePay.CheckResult ToCheckResult(string s, SagePay.CheckResult d = CheckResult.MATCHED)
			{
				SagePay.CheckResult t;
				return (Enum.TryParse<SagePay.CheckResult>(s, true, out t) ? t : d);
			}
			public static SagePay.AccountType ToAccountType(string s, SagePay.AccountType d = AccountType.Ecommerce)
			{
				SagePay.AccountType t;
				return (Enum.TryParse<SagePay.AccountType>(s, true, out t) ? t : d);
			}
			public static SagePay.Secure3DResult ToSecure3DResult(string s, SagePay.Secure3DResult d = Secure3DResult.OK)
			{
				SagePay.Secure3DResult t;
				return (Enum.TryParse<SagePay.Secure3DResult>(s, true, out t) ? t : d);
			}
			public static SagePay.TxState ToTxState(string s, SagePay.TxState d = TxState.None)
			{
				SagePay.TxState t;
				return (Enum.TryParse<SagePay.TxState>(s, true, out t) ? t : d);
			}
		}

		/// <summary>
		/// Internal class to hold and parse the SagePay xml response
		/// </summary>
		protected class SagePayResponse
		{
			/// <summary>
			/// Raw xml response object
			/// </summary>
			private XmlDocument m_responseXml;

			/// <summary>
			/// Create a new response object from the xml string
			/// </summary>
			/// <param name="responseXml"></param>
			public SagePayResponse(string responseXml)
			{
				// create our xml doc
				m_responseXml = new XmlDocument();
				m_responseXml.LoadXml(responseXml);

				// find an error node
				XmlNode node = m_responseXml.SelectSingleNode("//vspaccess/errorcode");
				int errorCode = 0;
				if (node != null && int.TryParse(node.InnerText, out errorCode) == true && errorCode != 0)
				{
					// there was an error and we have a non-zero error code
					ErrorCode = errorCode;
				}
				// pick out any error description
				node = m_responseXml.SelectSingleNode("//vspaccess/error");
				if (node != null && node.InnerText.Length != 0)
				{
					ErrorText = node.InnerText;
				}
				// pick out the timestamp
				node = m_responseXml.SelectSingleNode("//vspaccess/timestamp");
				if (node != null && node.InnerText.Length != 0)
				{
					DateTime dt;
					if (DateTime.TryParseExact(node.InnerText, "dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out dt) == true)
					{
						Timestamp = DateTime.SpecifyKind(dt, DateTimeKind.Utc).ToLocalTime();
					}
				}
			}

			/// <summary>
			/// Get the Error code
			/// </summary>
			public int ErrorCode { get; private set; }

			/// <summary>
			/// Get the error description
			/// </summary>
			public string ErrorText { get; private set; }

			/// <summary>
			/// Get the API timestamp
			/// </summary>
			public DateTime Timestamp { get; private set; }

			/// <summary>
			/// Get any field from the response set
			/// </summary>
			/// <param name="name">name of field</param>
			/// <returns>object value or null</returns>
			public string this[string name]
			{
				get
				{
					if (m_responseXml == null)
					{
						throw new SagePageResponseException("No response data set");
					}
					XmlNode node = m_responseXml.SelectSingleNode("//vspaccess/" + name);
					return (node != null ? node.InnerText : null);
				}
			}
		}
	}

	/// <summary>
	/// Class holding the Card Details
	/// </summary>
	public class SagePayCardDetails
	{
		public SagePay.CardType CardType { get; set; }
		public string Description { get; set; }
		public int IssueDigits { get; set; }
		public decimal MinBinRange { get; set; }
		public decimal MaxBinRange { get; set; }
		public string CountryCode { get; set; }
		public string Issuer { get; set; }
		public bool IsCorporate { get; set; }
		public bool IsCredit { get; set; }
	}

	/// <summary>
	/// Class holding a transaction's details
	/// </summary>
	public class SagePayTransactionDetails
	{
		public string TxID { get; set; }
		public string VendorTxCode { get; set; }
		public string TxType { get; set; }
		public SagePay.TxState TxStateId { get; set; }
		public string Status { get; set; }
		//
		public string RelatedTxId { get; set; }
		public string RelatedVendorTxCode { get; set; }
		public decimal RelatedAmount { get; set; }
		public string RelatedCurrency { get; set; }
		public DateTime RelatedStarted { get; set; }
		//
		public string Description { get; set; }
		public decimal Amount { get; set; }
		public string Currency { get; set; }
		public DateTime Started { get; set; }
		public DateTime Completed { get; set; }
		//
		public string SecurityKey { get; set; }
		public string ClientIP { get; set; }
		public string GiftAid { get; set; }
		public string PaymentSystem { get; set; }
		public string PaymentSystemDetails { get; set; }
		public string StartDate { get; set; }
		public string ExpiryDate { get; set; }
		public string Last4Digits { get; set; }
		public string AuthProcessor { get; set; }
		public string MerchantNumber { get; set; }
		public SagePay.AccountType AccountType { get; set; }
		public long AuthCode { get; set; }
		public string BankAuthCode { get; set; }
		public int BatchId { get; set; }
		//
		// ignoring billing, delivery, card fields for now...
		//
		public SagePay.CheckResult CV2Result { get; set; }
		public SagePay.CheckResult AddressResult { get; set; }
		public SagePay.CheckResult PostcodeResult { get; set; }
		//
		public int Secure3DAttempts { get; set; }
		public SagePay.Secure3DResult Secure3DResult { get; set; }
		public int T3MScore { get; set; }
		public string T3MAction { get; set; }
	}


	/// <summary>
	/// Base sagepay exception class
	/// </summary>
	public class SagePageException : ApplicationException
	{
		/// <summary>
		/// Create a new exception
		/// </summary>
		/// <param name="message">optional message</param>
		/// <param name="ex">optional innner exception</param>
		public SagePageException(string message = null, Exception ex = null) : base(message, ex) { }
	}

	/// <summary>
	/// Exception for invalid response
	/// </summary>
	public class SagePageResponseException : SagePageException
	{
		public SagePageResponseException(string message) : base(message) { }
	}

	/// <summary>
	/// Exception object for error returned from SP call
	/// </summary>
	public class SagePageErrorException : SagePageException
	{
		public SagePageErrorException(int errorCode, string message) : base(errorCode.ToString() + ": " + message) { }
	}

	/// <summary>
	/// Exception object for unknown card type
	/// </summary>
	public class SagePageUnknownCardException : SagePageException
	{
		public SagePageUnknownCardException(string message) : base(message) { }
	}

}
