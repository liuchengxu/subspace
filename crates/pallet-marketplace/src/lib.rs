// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pallet NFT Marketplace

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(array_windows)]

use frame_support::traits::Currency;
pub use pallet::*;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[frame_support::pallet]
mod pallet {
    use super::BalanceOf;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, ExistenceRequirement};
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: Currency<Self::AccountId>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::error]
    pub enum Error<T> {
        ItemUnavailable,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new item on the shelf.
        NewItem {
            item_index: ItemIndex,
            price: BalanceOf<T>,
        },
        /// An item was sold.
        Sold {
            item_index: ItemIndex,
            buyer: T::AccountId,
        },
    }

    #[pallet::storage]
    pub(super) type Items<T: Config> =
        StorageMap<_, Identity, ItemIndex, (T::AccountId, BalanceOf<T>), OptionQuery>;

    pub type ItemIndex = u32;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn sell(
            origin: OriginFor<T>,
            item_index: ItemIndex,
            price: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Ensure `who` is the owner of this item.

            // Put item on the shelf.
            Items::<T>::insert(item_index, (who, price));

            Self::deposit_event(Event::NewItem { item_index, price });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn buy(origin: OriginFor<T>, item_index: ItemIndex) -> DispatchResult {
            let buyer = ensure_signed(origin)?;

            let (seller, price) = Items::<T>::get(item_index).ok_or(Error::<T>::ItemUnavailable)?;

            T::Currency::transfer(&buyer, &seller, price, ExistenceRequirement::KeepAlive)?;

            Self::deposit_event(Event::Sold { item_index, buyer });

            Ok(())
        }
    }
}
