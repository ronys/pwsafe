/*
 * Created by Saurav Ghosh on 19/06/16.
 * Copyright (c) 2003-2025 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

#include "stdafx.h"
#include "argutils.h"
#include "./strutils.h"

#include <map>
#include <regex>
#include <cassert>

#include "../../core/PWScore.h"
#include "../../core/core.h"

using namespace std;

using String2FieldTypeMap = std::map<stringT, CItemData::FieldType>;

const std::map<int, CItemData::FieldType> id2enum = {
	{IDSC_FLDNMGROUPTITLE,     CItem::GROUPTITLE},
	{IDSC_FLDNMUUID,           CItem::UUID},
	{IDSC_FLDNMGROUP,          CItem::GROUP},
	{IDSC_FLDNMTITLE,          CItem::TITLE},
	{IDSC_FLDNMUSERNAME,       CItem::USER},
	{IDSC_FLDNMNOTES,          CItem::NOTES},
	{IDSC_FLDNMPASSWORD,       CItem::PASSWORD},
	{IDSC_FLDNMTWOFACTORKEY,   CItem::TWOFACTORKEY},
#undef CTIME
	{IDSC_FLDNMCTIME,          CItem::CTIME},
	{IDSC_FLDNMPMTIME,         CItem::PMTIME},
	{IDSC_FLDNMATIME,          CItem::ATIME},
	{IDSC_FLDNMXTIME,          CItem::XTIME},
	{IDSC_FLDNMRMTIME,         CItem::RMTIME},
	{IDSC_FLDNMURL,            CItem::URL},
	{IDSC_FLDNMAUTOTYPE,       CItem::AUTOTYPE},
	{IDSC_FLDNMPWHISTORY,      CItem::PWHIST},
	{IDSC_FLDNMPWPOLICY,       CItem::POLICY},
	{IDSC_FLDNMXTIMEINT,       CItem::XTIME_INT},
	{IDSC_FLDNMRUNCOMMAND,     CItem::RUNCMD},
	{IDSC_FLDNMDCA,            CItem::DCA},
	{IDSC_FLDNMSHIFTDCA,       CItem::SHIFTDCA},
	{IDSC_FLDNMEMAIL,          CItem::EMAIL},
	{IDSC_FLDNMPROTECTED,      CItem::PROTECTED},
	{IDSC_FLDNMSYMBOLS,        CItem::SYMBOLS},
	{IDSC_FLDNMPWPOLICYNAME,   CItem::POLICYNAME},
	{IDSC_FLDNMKBSHORTCUT,     CItem::KBSHORTCUT},
	{IDSC_FLDNMTOTPCONFIG,     CItem::TOTPCONFIG},
	{IDSC_FLDNMTOTPLENGTH,     CItem::TOTPLENGTH},
	{IDSC_FLDNMTOTPTIMESTEP,   CItem::TOTPTIMESTEP},
	{IDSC_FLDNMTOTPSTARTTIME,  CItem::TOTPSTARTTIME},
	{IDSC_FLDNMDATAATTTITLE,       CItem::DATA_ATT_TITLE},
	{IDSC_FLDNMDATAATTMEDIATYPE,   CItem::DATA_ATT_MEDIATYPE},
	{IDSC_FLDNMDATAATTFILENAME,    CItem::DATA_ATT_FILENAME},
	{IDSC_FLDNMDATAATTMTIME,       CItem::DATA_ATT_MTIME},
	{IDSC_FLDNMDATAATTCONTENT,     CItem::DATA_ATT_CONTENT},
};

std::vector<stringT> GetValidFieldNames() {
	std::vector<stringT> fields;
	using map_value_type = decltype(*id2enum.begin());

	std::transform( id2enum.begin(), id2enum.end(), std::back_inserter(fields), [](map_value_type itr) {
			stringT s;
			LoadAString(s, itr.first);
			return s;
	});

	return fields;
}

// Reverse of CItemData::FieldName
static String2FieldTypeMap  InitFieldTypeMap()
{
  String2FieldTypeMap ftmap;
  for ( auto itr: id2enum ) {
	  stringT retval;
	  LoadAString(retval, itr.first);
	  ftmap[retval] = itr.second;
  }
  return ftmap;;
}

CItemData::FieldType String2FieldType(const stringT& str)
{
  static const String2FieldTypeMap ftmap = InitFieldTypeMap();
  stringT s{str}; // Trim requires non-const
  auto itr = ftmap.find(Trim(s));
  if (itr != ftmap.end())
    return itr->second;
  throw std::invalid_argument("Invalid field: " + toutf8(str));
}

PWSMatch::MatchRule Str2MatchRule( const wstring &s)
{
  static const std::map<wstring, PWSMatch::MatchRule> rulemap{
    {L"==", PWSMatch::MR_EQUALS},
    {L"!==", PWSMatch::MR_NOTEQUAL},
    {L"^=", PWSMatch::MR_BEGINS},
    {L"!^=", PWSMatch::MR_NOTBEGIN},
    {L"$=", PWSMatch::MR_ENDS},
    {L"!$=", PWSMatch::MR_NOTEND},
    {L"~=", PWSMatch::MR_CONTAINS},
    {L"!~=", PWSMatch::MR_NOTCONTAIN}
  };
  const auto itr = rulemap.find(s);
  if ( itr != rulemap.end() )
    return itr->second;
  return PWSMatch::MR_INVALID;
}

CItemData::FieldBits ParseFields(const wstring &f)
{
  CItemData::FieldBits fields;
  Split(f, L",", [&fields](const wstring &field) {
    CItemData::FieldType ft = String2FieldType(field);
    fields.set(ft);
  });
  return fields;
}

void UserArgs::SetFields(const wstring &f)
{
  fields = ParseFields(f);
}

inline bool CaseSensitive(const wstring &str)
{
  assert(str.length() == 0 || (str.length() == 2 && str[0] == '/' && (str[1] == L'i' || str[1] == 'I')));
  return str.length() == 0 || str[0] == L'i';
}

Restriction ParseSubset(const std::wstring &s)
{
  const std::wregex restrictPattern{L"([[:alpha:]-]+)([!]?[=^$~]=)([^;]+?)(/[iI])?$"};
  wsmatch m;
  if (regex_search(s, m, restrictPattern))
    return Restriction{String2FieldType(m.str(1)), Str2MatchRule(m.str(2)), m.str(3), CaseSensitive(m.str(4))};
  throw std::invalid_argument("Invalid subset: " + toutf8(s));
}


void UserArgs::SetSubset(const std::wstring &s)
{
  subset = ParseSubset(s);
}

#include "../../os/file.h"
#include <cstdlib>

UserArgs::FieldUpdates ParseFieldValues(const wstring &updates)
{
  UserArgs::FieldUpdates fieldValues;
  Split(updates, L"[;,]", [&fieldValues](const wstring &nameval) {
    std::wsmatch m;
    if (std::regex_match(nameval, m, std::wregex(L"([^=:]+?)[=:](.+)"))) {
      CItemData::FieldType ft = String2FieldType(m.str(1));
      StringX val = std2stringx(m.str(2));
      if (ft == CItemData::DATA_ATT_CONTENT && !val.empty() && val[0] == '@') {
        std::wstring filename(val.substr(1).c_str());
        std::FILE *fp = pws_os::FOpen(filename, L"rb");
        if (fp) {
          size_t len = pws_os::fileLength(fp);
          char* content = new char[len + 1];
          fread(content, 1, len, fp);
          pws_os::FClose(fp, false);
          content[len] = '\0';
          wchar_t* wcontent = new wchar_t[len + 1];
          mbstowcs(wcontent, content, len + 1);
          val = StringX(wcontent);
          delete[] content;
          delete[] wcontent;
        } else {
          throw std::invalid_argument{"Could not open file: " + toutf8(filename)};
        }
      }
      fieldValues.push_back(std::make_tuple(ft, val));
    }
    else {
      throw std::invalid_argument{"Could not parse field value to be updated: " + toutf8(nameval)};
    }
  });
  return fieldValues;
}

void UserArgs::SetFieldValues(const wstring &updates) {
  fieldValues = ParseFieldValues(updates);
}
